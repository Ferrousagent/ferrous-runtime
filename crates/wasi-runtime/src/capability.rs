//! Explicit authority granted to one Ferrous execution session.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Errors produced while constructing a capability grant.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    /// A path was not absolute or contained a parent-directory component.
    #[error("capability path must be absolute and cannot contain `..`: {0}")]
    InvalidPath(PathBuf),
    /// A resource limit was zero and could not bound the operation.
    #[error("{name} must be greater than zero")]
    InvalidLimit {
        /// Name of the invalid limit.
        name: &'static str,
    },
    /// An environment variable name was malformed.
    #[error("invalid environment variable name: {0}")]
    InvalidEnvironmentName(String),
    /// A loopback port of zero was allowlisted; port 0 has no legitimate
    /// meaning and on bind means "any ephemeral port".
    #[error("loopback port must be greater than zero: {0}")]
    InvalidLoopbackPort(u16),
}

/// Filesystem authority for one granted root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemAccess {
    /// Read files and list directories.
    Read,
    /// Read, create, modify, rename, and remove within the root.
    ReadWrite,
}

/// A filesystem root and the operations allowed below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemGrant {
    root: PathBuf,
    access: FilesystemAccess,
}

impl FilesystemGrant {
    /// Construct a grant for an absolute, lexically safe root.
    pub fn new(
        root: impl Into<PathBuf>,
        access: FilesystemAccess,
    ) -> Result<Self, CapabilityError> {
        let root = root.into();
        validate_path(&root)?;
        Ok(Self { root, access })
    }

    /// Return the granted root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the granted access level.
    pub const fn access(&self) -> FilesystemAccess {
        self.access
    }

    fn allows(&self, path: &Path) -> bool {
        is_safe_absolute_path(path) && path.starts_with(&self.root)
    }

    pub(crate) fn guest_path_for(&self, path: &Path, guest_root: &str) -> Option<String> {
        if !self.allows(path) {
            return None;
        }
        let relative = path.strip_prefix(&self.root).ok()?;
        let guest_path = if relative.as_os_str().is_empty() {
            PathBuf::from(guest_root)
        } else {
            PathBuf::from(guest_root).join(relative)
        };
        guest_path.to_str().map(str::to_owned)
    }
}

/// Limits applied to one command/session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    max_output_bytes: usize,
    timeout_seconds: u64,
    max_memory_bytes: usize,
    max_fuel: u64,
}

const DEFAULT_LIMITS: ResourceLimits = ResourceLimits {
    max_output_bytes: 1_048_576,
    timeout_seconds: 30,
    max_memory_bytes: 64 * 1024 * 1024,
    max_fuel: 1_000_000,
};

impl ResourceLimits {
    /// Construct limits that can bound output and wall-clock execution.
    pub const fn new(
        max_output_bytes: usize,
        timeout_seconds: u64,
    ) -> Result<Self, CapabilityError> {
        if max_output_bytes == 0 {
            return Err(CapabilityError::InvalidLimit {
                name: "max_output_bytes",
            });
        }
        if timeout_seconds == 0 {
            return Err(CapabilityError::InvalidLimit {
                name: "timeout_seconds",
            });
        }
        Ok(Self {
            max_output_bytes,
            timeout_seconds,
            max_memory_bytes: DEFAULT_LIMITS.max_memory_bytes,
            max_fuel: DEFAULT_LIMITS.max_fuel,
        })
    }

    /// Set the maximum guest fuel (instructions) before the runtime traps it.
    pub const fn with_fuel(mut self, max_fuel: u64) -> Result<Self, CapabilityError> {
        if max_fuel == 0 {
            return Err(CapabilityError::InvalidLimit { name: "max_fuel" });
        }
        self.max_fuel = max_fuel;
        Ok(self)
    }

    /// Raise the instruction-count bound beyond any practical execution so the
    /// guest runs until the wall-clock timeout (or cancellation) stops it.
    pub const fn with_unlimited_fuel(mut self) -> Self {
        self.max_fuel = u64::MAX;
        self
    }

    /// Set the maximum size of each guest linear memory.
    pub const fn with_memory_bytes(
        mut self,
        max_memory_bytes: usize,
    ) -> Result<Self, CapabilityError> {
        if max_memory_bytes == 0 {
            return Err(CapabilityError::InvalidLimit {
                name: "max_memory_bytes",
            });
        }
        self.max_memory_bytes = max_memory_bytes;
        Ok(self)
    }

    /// Maximum output budget for the session.
    ///
    /// Each stream's pipe traps the guest once it alone reaches this size, and
    /// the streaming path additionally cuts the guest off once stdout and
    /// stderr *together* exceed it, so a guest cannot write twice the declared
    /// budget by splitting its output across streams.
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }

    /// Maximum wall-clock duration in seconds.
    pub const fn timeout_seconds(self) -> u64 {
        self.timeout_seconds
    }

    /// Maximum guest fuel (instructions) before the runtime traps it.
    pub const fn max_fuel(self) -> u64 {
        self.max_fuel
    }

    /// Maximum size of each guest linear memory.
    pub const fn max_memory_bytes(self) -> usize {
        self.max_memory_bytes
    }
}

/// The complete authority available to one command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrant {
    filesystems: Vec<FilesystemGrant>,
    environment: BTreeSet<String>,
    /// Loopback TCP ports the guest may *connect to*.
    loopback_ports: BTreeSet<u16>,
    /// Loopback TCP ports the guest may *bind*. Empty by default: binding is
    /// denied unless explicitly granted, because a bound port can be observed
    /// and hijacked by other local processes.
    loopback_bind_ports: BTreeSet<u16>,
    native_execution: bool,
    limits: ResourceLimits,
}

impl CapabilityGrant {
    /// Create a grant with no filesystem, environment, network, or native authority.
    pub fn empty() -> Self {
        Self {
            filesystems: Vec::new(),
            environment: BTreeSet::new(),
            loopback_ports: BTreeSet::new(),
            loopback_bind_ports: BTreeSet::new(),
            native_execution: false,
            limits: DEFAULT_LIMITS,
        }
    }

    /// Grant access below one workspace root.
    pub fn workspace(
        root: impl Into<PathBuf>,
        access: FilesystemAccess,
    ) -> Result<Self, CapabilityError> {
        let mut grant = Self::empty();
        grant.filesystems.push(FilesystemGrant::new(root, access)?);
        Ok(grant)
    }

    /// Add an environment variable name to the allowlist.
    pub fn allow_environment(mut self, name: impl Into<String>) -> Result<Self, CapabilityError> {
        let name = name.into();
        if name.is_empty()
            || name.contains('=')
            || name
                .chars()
                .any(|character| character == '\0' || character.is_whitespace())
        {
            return Err(CapabilityError::InvalidEnvironmentName(name));
        }
        self.environment.insert(name);
        Ok(self)
    }

    /// Allow the guest to *connect to* one loopback TCP port.
    ///
    /// Port 0 is rejected: it has no legitimate allowlist meaning, and for a
    /// bind it would expand to "any ephemeral port".
    pub fn allow_loopback_port(mut self, port: u16) -> Result<Self, CapabilityError> {
        if port == 0 {
            return Err(CapabilityError::InvalidLoopbackPort(port));
        }
        self.loopback_ports.insert(port);
        Ok(self)
    }

    /// Allow the guest to *bind* one loopback TCP port.
    ///
    /// Binding is denied unless explicitly granted: a guest that binds an
    /// allowlisted connect port could impersonate the service the operator
    /// intended to reach. Allowing a bind is an approval-gated decision.
    pub fn allow_loopback_bind_port(mut self, port: u16) -> Result<Self, CapabilityError> {
        if port == 0 {
            return Err(CapabilityError::InvalidLoopbackPort(port));
        }
        self.loopback_bind_ports.insert(port);
        Ok(self)
    }

    /// Allow the native process backend for this command.
    pub fn allow_native_execution(mut self) -> Self {
        self.native_execution = true;
        self
    }

    /// Replace the resource limits for this command.
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Whether a path is lexically within one of the granted roots.
    ///
    /// This check is intentionally allocation-free, but it does not resolve symlinks.
    /// Runtime code handling a host path must use [`Self::allows_existing_path`] instead.
    pub fn allows_path(&self, path: &Path) -> bool {
        self.filesystems.iter().any(|grant| grant.allows(path))
    }

    /// Whether an existing host path remains within a grant after symlink resolution.
    ///
    /// The nearest existing ancestor is canonicalized, so this also handles a new leaf
    /// below an existing symlink. A path whose root does not exist is denied rather than
    /// treated as safe by a lexical prefix check.
    pub fn allows_existing_path(&self, path: &Path) -> bool {
        if !self.allows_path(path) {
            return false;
        }
        let Some(resolved_path) = canonicalize_with_existing_parent(path) else {
            return false;
        };
        self.filesystems.iter().any(|grant| {
            let Ok(resolved_root) = fs::canonicalize(grant.root()) else {
                return false;
            };
            resolved_path.starts_with(resolved_root)
        })
    }

    pub(crate) fn filesystem_grants(&self) -> impl Iterator<Item = &FilesystemGrant> {
        self.filesystems.iter()
    }

    /// Whether an environment variable name is allowed.
    pub fn allows_environment(&self, name: &str) -> bool {
        self.environment.contains(name)
    }

    pub(crate) fn environment_names(&self) -> impl Iterator<Item = &str> {
        self.environment.iter().map(String::as_str)
    }

    pub(crate) fn loopback_ports(&self) -> &BTreeSet<u16> {
        &self.loopback_ports
    }

    pub(crate) fn loopback_bind_ports(&self) -> &BTreeSet<u16> {
        &self.loopback_bind_ports
    }

    /// Whether a loopback TCP port is allowed for *connecting*.
    pub fn allows_loopback_port(&self, port: u16) -> bool {
        self.loopback_ports.contains(&port)
    }

    /// Whether a loopback TCP port is allowed for *binding*.
    pub fn allows_loopback_bind_port(&self, port: u16) -> bool {
        self.loopback_bind_ports.contains(&port)
    }

    /// Whether native process execution was explicitly granted.
    pub const fn allows_native_execution(&self) -> bool {
        self.native_execution
    }

    /// Return the command's limits.
    pub const fn limits(&self) -> ResourceLimits {
        self.limits
    }
}

fn canonicalize_with_existing_parent(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    let mut suffix = Vec::new();

    loop {
        if let Ok(mut resolved) = fs::canonicalize(&current) {
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }

        let file_name = current.file_name()?.to_os_string();
        suffix.push(PathBuf::from(file_name));
        if !current.pop() {
            return None;
        }
    }
}

fn validate_path(path: &Path) -> Result<(), CapabilityError> {
    if !is_safe_absolute_path(path) {
        return Err(CapabilityError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_and_parent_paths() {
        assert!(matches!(
            FilesystemGrant::new("workspace", FilesystemAccess::Read),
            Err(CapabilityError::InvalidPath(_))
        ));
        assert!(matches!(
            FilesystemGrant::new("/workspace/../secrets", FilesystemAccess::Read),
            Err(CapabilityError::InvalidPath(_))
        ));
    }

    #[test]
    fn rejects_zero_fuel_and_zero_memory_limits() {
        let limits = ResourceLimits::new(1024, 30).expect("valid limits");
        assert!(limits.with_fuel(0).is_err());
        assert!(limits.with_memory_bytes(0).is_err());
        assert_eq!(limits.max_fuel(), 1_000_000);
    }

    #[test]
    fn unlimited_fuel_uses_the_sentinel() {
        let limits = ResourceLimits::new(1024, 30).expect("valid limits");
        assert_eq!(limits.with_unlimited_fuel().max_fuel(), u64::MAX);
    }

    #[test]
    fn rejects_malformed_environment_names() {
        let result = CapabilityGrant::empty().allow_environment("TOKEN=value");
        assert!(matches!(
            result,
            Err(CapabilityError::InvalidEnvironmentName(_))
        ));
    }

    #[test]
    fn rejects_port_zero_on_connect_and_bind() {
        assert!(matches!(
            CapabilityGrant::empty().allow_loopback_port(0),
            Err(CapabilityError::InvalidLoopbackPort(0))
        ));
        assert!(matches!(
            CapabilityGrant::empty().allow_loopback_bind_port(0),
            Err(CapabilityError::InvalidLoopbackPort(0))
        ));
    }

    #[test]
    fn bind_allowlist_is_separate_and_empty_by_default() {
        let grant = CapabilityGrant::empty()
            .allow_loopback_port(3000)
            .expect("valid connect port");
        assert!(grant.allows_loopback_port(3000));
        // Connect allowlist does not imply bind permission.
        assert!(!grant.allows_loopback_bind_port(3000));

        let grant = grant
            .allow_loopback_bind_port(3001)
            .expect("valid bind port");
        assert!(grant.allows_loopback_bind_port(3001));
        assert!(!grant.allows_loopback_port(3001));
        assert!(!grant.allows_loopback_bind_port(3000));
    }

    #[cfg(unix)]
    #[test]
    fn existing_path_check_rejects_a_symlink_that_leaves_the_grant() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("ferrous-capability-root-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("ferrous-capability-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).expect("grant root is created");
        std::fs::create_dir_all(&outside).expect("outside directory is created");
        std::fs::write(outside.join("secret.txt"), b"secret").expect("outside file is created");
        symlink(&outside, root.join("link")).expect("symlink is created");

        let grant = CapabilityGrant::workspace(&root, FilesystemAccess::Read)
            .expect("temporary root is absolute");
        let escaped = root.join("link/secret.txt");

        assert!(grant.allows_path(&escaped));
        assert!(!grant.allows_existing_path(&escaped));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
