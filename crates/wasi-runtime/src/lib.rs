//! `wasi-runtime` — the safe execution boundary for Ferrous tools and terminals.
//!
//! Phase 1 keeps the public contract independent of the eventual Tauri UI. The CLI and
//! future Tauri bridge consume the same capability and terminal-session types.

#![forbid(unsafe_code)]

pub mod broker;
pub mod cancel;
pub mod capability;
pub mod command;
pub mod native;
pub mod pipe;
pub mod policy;

use std::sync::mpsc;
use std::time::Duration;

use thiserror::Error;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxView, WasiView};

use crate::cancel::CancelHandle;
use crate::capability::FilesystemAccess;
use crate::command::{CommandError, CommandRequest, ExecutionMode, SessionEvent, Stream};
use crate::pipe::StreamOutputPipe;

/// Errors produced while creating the runtime or admitting a component.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The Wasmtime engine could not be configured.
    #[error("failed to create Wasmtime engine: {0}")]
    Engine(#[source] wasmtime::Error),
    /// The component was malformed or could not be compiled safely.
    #[error("component admission failed: {0}")]
    Component(#[source] wasmtime::Error),
    /// The request was not valid for the selected backend.
    #[error("invalid WASI request: {0}")]
    Command(#[from] CommandError),
    /// WASI linker, context, or guest execution failed.
    #[error("WASI execution failed: {0}")]
    Wasi(#[source] wasmtime::Error),
    /// A non-WASI request was passed to the WASI backend.
    #[error("WASI backend received a non-WASI request")]
    WrongMode,
    /// The session was cancelled before the guest completed.
    #[error("session was cancelled")]
    Cancelled,
}

/// Captured output and exit status from one WASI command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasiOutput {
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// `0` for success, `1` for a guest-reported failure.
    pub exit_code: i32,
}

struct StoreState {
    ctx: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for StoreState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

/// The embedded Wasmtime runtime configured for Ferrous's safe admission path.
pub struct WasiRuntime {
    engine: wasmtime::Engine,
}

impl WasiRuntime {
    /// Return the engine this runtime compiles and runs components on.
    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    /// Create the production Phase 1 engine configuration.
    pub fn new() -> Result<Self, RuntimeError> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true).epoch_interruption(true);
        let engine = wasmtime::Engine::new(&config).map_err(RuntimeError::Engine)?;
        Ok(Self { engine })
    }

    /// Safely validate and compile raw component bytes.
    ///
    /// Serialized/AOT artifacts are deliberately not accepted here. This method uses
    /// Wasmtime's safe raw-component admission path and keeps the compiled handle in memory.
    pub fn compile_component(&self, bytes: &[u8]) -> Result<Component, RuntimeError> {
        Component::new(&self.engine, bytes).map_err(RuntimeError::Component)
    }

    /// Run one previously admitted WASI command with explicit capabilities.
    pub fn run_wasi(
        &self,
        component: &Component,
        request: &CommandRequest,
    ) -> Result<WasiOutput, RuntimeError> {
        self.run_wasi_inner(component, request, None)
    }

    /// Run one previously admitted WASI command with cancellation support.
    ///
    /// Once the handle is cancelled the guest is interrupted at its next epoch
    /// check and [`RuntimeError::Cancelled`] is returned. A finished or never
    /// started run is unaffected.
    pub fn run_wasi_cancellable(
        &self,
        component: &Component,
        request: &CommandRequest,
        cancel: &CancelHandle,
    ) -> Result<WasiOutput, RuntimeError> {
        self.run_wasi_inner(component, request, Some(cancel))
    }

    /// Run one previously admitted WASI command while streaming live events.
    ///
    /// Emits [`SessionEvent::Output`] chunks to `events` as the guest produces
    /// them, then returns the captured output and exit status. The output
    /// budget is enforced structurally by the bounded pipes; cancellation and
    /// the wall-clock timeout behave exactly as in
    /// [`Self::run_wasi_cancellable`].
    pub fn run_wasi_events(
        &self,
        component: &Component,
        request: &CommandRequest,
        cancel: &CancelHandle,
        events: &mpsc::Sender<SessionEvent>,
    ) -> Result<WasiOutput, RuntimeError> {
        self.run_wasi_events_impl(component, request, cancel, events, &|name| {
            std::env::var(name).ok()
        })
    }

    /// Shared streaming implementation with an injectable environment provider.
    fn run_wasi_events_impl(
        &self,
        component: &Component,
        request: &CommandRequest,
        cancel: &CancelHandle,
        events: &mpsc::Sender<SessionEvent>,
        env_provider: &dyn Fn(&str) -> Option<String>,
    ) -> Result<WasiOutput, RuntimeError> {
        let stdout = StreamOutputPipe::new(request.grant.limits().max_output_bytes());
        let stderr = StreamOutputPipe::new(request.grant.limits().max_output_bytes());
        let (mut store, linker) =
            self.build_store(request, stdout.clone(), stderr.clone(), env_provider)?;
        let epoch_ticks = request
            .grant
            .limits()
            .timeout_seconds()
            .saturating_mul(10)
            .max(1);

        // A reader thread drains both pipes while this thread runs the guest.
        // It also serves as the epoch watchdog: cancellation bursts past the
        // deadline, and a tick every ~100ms enforces the wall-clock timeout.
        let engine = self.engine.clone();
        let reader_cancel = cancel.clone();
        let events_tx = events.clone();
        let reader_stdout = stdout.clone();
        let reader_stderr = stderr.clone();
        let reader = std::thread::spawn(move || {
            let mut last_tick = std::time::Instant::now();
            let mut total_stdout = Vec::new();
            let mut total_stderr = Vec::new();
            loop {
                let (out_bytes, out_eof) = reader_stdout.wait_and_drain(Duration::from_millis(50));
                if !out_bytes.is_empty() {
                    total_stdout.extend_from_slice(&out_bytes);
                    let _ = events_tx.send(SessionEvent::Output {
                        stream: Stream::Stdout,
                        bytes: out_bytes,
                    });
                }
                let (err_bytes, err_eof) = reader_stderr.wait_and_drain(Duration::from_millis(50));
                if !err_bytes.is_empty() {
                    total_stderr.extend_from_slice(&err_bytes);
                    let _ = events_tx.send(SessionEvent::Output {
                        stream: Stream::Stderr,
                        bytes: err_bytes,
                    });
                }
                if reader_cancel.is_cancelled() {
                    // Burst past the deadline so the guest traps at its next
                    // epoch check instead of waiting out the wall-clock timeout.
                    for _ in 0..epoch_ticks {
                        engine.increment_epoch();
                    }
                } else if last_tick.elapsed() >= Duration::from_millis(100) {
                    engine.increment_epoch();
                    last_tick = std::time::Instant::now();
                }
                if out_eof && err_eof {
                    break;
                }
            }
            (total_stdout, total_stderr)
        });

        let command = match wasmtime_wasi::p2::bindings::sync::Command::instantiate(
            &mut store, component, &linker,
        ) {
            Ok(command) => command,
            Err(error) => {
                // Release the reader even when the guest never started.
                drop(store);
                stdout.set_eof();
                stderr.set_eof();
                let _ = reader.join();
                return Err(RuntimeError::Wasi(error));
            }
        };
        let run_result = command.wasi_cli_run().call_run(&mut store);
        // The store owned the only writers; dropping it closes both pipes.
        drop(store);
        stdout.set_eof();
        stderr.set_eof();
        let (stdout_bytes, stderr_bytes) = reader
            .join()
            .map_err(|_| RuntimeError::Wasi(wasmtime::Error::msg("output reader thread failed")))?;

        match run_result {
            Ok(Ok(())) => Ok(WasiOutput {
                stdout: stdout_bytes,
                stderr: stderr_bytes,
                exit_code: 0,
            }),
            Ok(Err(())) => Ok(WasiOutput {
                stdout: stdout_bytes,
                stderr: stderr_bytes,
                exit_code: 1,
            }),
            Err(error) => {
                if cancel.is_cancelled() {
                    Err(RuntimeError::Cancelled)
                } else {
                    Err(RuntimeError::Wasi(error))
                }
            }
        }
    }

    /// Build a store and linker for one request with the given stdio sinks.
    ///
    /// Shared by the capturing and streaming paths so both get exactly the
    /// same capability, environment, and network posture.
    fn build_store(
        &self,
        request: &CommandRequest,
        stdout: impl wasmtime_wasi::cli::StdoutStream + 'static,
        stderr: impl wasmtime_wasi::cli::StdoutStream + 'static,
        env_provider: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(wasmtime::Store<StoreState>, Linker<StoreState>), RuntimeError> {
        request.validate()?;
        if request.mode != ExecutionMode::Wasi {
            return Err(RuntimeError::WrongMode);
        }
        if !request.grant.allows_existing_path(&request.cwd) {
            return Err(RuntimeError::Command(CommandError::WorkingDirectoryDenied(
                request.cwd.clone(),
            )));
        }

        let mut builder = WasiCtx::builder();
        builder.args(&request.args);
        builder.initial_cwd("/workspace");
        builder.stdout(stdout);
        builder.stderr(stderr);

        // Environment: only allowlisted names propagate from the host process.
        // The allowlist is the policy; a name that is not granted is never read.
        for (name, value) in policy::selected_environment(&request.grant, env_provider) {
            builder.env(name, value);
        }
        // Networking: explicit default-deny. Without this, wasmtime's socket
        // posture is an undocumented default; Ferrous makes it a tested policy.
        let network = policy::NetworkPolicy::from_grant(&request.grant);
        network.apply(&mut builder);

        let mut cwd_guest = None;
        for (index, filesystem) in request.grant.filesystem_grants().enumerate() {
            let guest_root = if index == 0 {
                "/workspace".to_owned()
            } else {
                format!("/grant-{index}")
            };
            let dir_perms = match filesystem.access() {
                FilesystemAccess::Read => DirPerms::READ,
                FilesystemAccess::ReadWrite => DirPerms::all(),
            };
            let file_perms = match filesystem.access() {
                FilesystemAccess::Read => FilePerms::READ,
                FilesystemAccess::ReadWrite => FilePerms::all(),
            };
            let host_root = std::fs::canonicalize(filesystem.root()).map_err(|_| {
                RuntimeError::Command(CommandError::WorkingDirectoryDenied(
                    filesystem.root().to_path_buf(),
                ))
            })?;
            builder
                .preopened_dir(&host_root, &guest_root, dir_perms, file_perms)
                .map_err(RuntimeError::Wasi)?;
            if cwd_guest.is_none() {
                cwd_guest = filesystem.guest_path_for(&request.cwd, &guest_root);
            }
        }
        if let Some(cwd_guest) = cwd_guest {
            builder.initial_cwd(cwd_guest);
        }

        let mut linker = Linker::<StoreState>::new(&self.engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(RuntimeError::Wasi)?;
        let mut store = wasmtime::Store::new(
            &self.engine,
            StoreState {
                ctx: builder.build(),
                table: ResourceTable::new(),
                limits: StoreLimitsBuilder::new()
                    .memory_size(request.grant.limits().max_memory_bytes())
                    .instances(16)
                    .tables(16)
                    .memories(16)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        // Fuel bounds guest work; `with_unlimited_fuel` raises it beyond any
        // practical execution. The wall-clock epoch deadline stays the hard
        // limit either way. (Fuel accounting itself is engine-level config and
        // always on for the Phase 1 engine.)
        store
            .set_fuel(request.grant.limits().max_fuel())
            .map_err(RuntimeError::Wasi)?;
        let epoch_ticks = request
            .grant
            .limits()
            .timeout_seconds()
            .saturating_mul(10)
            .max(1);
        store.set_epoch_deadline(epoch_ticks);
        Ok((store, linker))
    }

    fn run_wasi_inner(
        &self,
        component: &Component,
        request: &CommandRequest,
        cancel: Option<&CancelHandle>,
    ) -> Result<WasiOutput, RuntimeError> {
        let stdout = wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(
            request.grant.limits().max_output_bytes(),
        );
        let stderr = wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(
            request.grant.limits().max_output_bytes(),
        );
        let (mut store, linker) =
            self.build_store(request, stdout.clone(), stderr.clone(), &|name| {
                std::env::var(name).ok()
            })?;
        let epoch_ticks = request
            .grant
            .limits()
            .timeout_seconds()
            .saturating_mul(10)
            .max(1);

        let command =
            wasmtime_wasi::p2::bindings::sync::Command::instantiate(&mut store, component, &linker)
                .map_err(RuntimeError::Wasi)?;
        let (stop_sender, stop_receiver) = mpsc::channel();
        let engine = self.engine.clone();
        let cancel = cancel.cloned();
        let watchdog_cancel = cancel.clone();
        let watchdog = std::thread::spawn(move || {
            let mut ticks = 0u64;
            loop {
                if let Some(cancel) = &watchdog_cancel {
                    if cancel.is_cancelled() {
                        // Burst past the guest's deadline so it traps at its next
                        // epoch check instead of waiting out the wall-clock timeout.
                        for _ in 0..epoch_ticks {
                            engine.increment_epoch();
                        }
                        return;
                    }
                }
                if ticks >= epoch_ticks {
                    return;
                }
                match stop_receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        engine.increment_epoch();
                        ticks += 1;
                    }
                }
            }
        });
        let run_result = command.wasi_cli_run().call_run(&mut store);
        let _ = stop_sender.send(());
        let _ = watchdog.join();
        match run_result {
            Ok(Ok(())) => Ok(WasiOutput {
                stdout: stdout.contents().to_vec(),
                stderr: stderr.contents().to_vec(),
                exit_code: 0,
            }),
            Ok(Err(())) => Ok(WasiOutput {
                stdout: stdout.contents().to_vec(),
                stderr: stderr.contents().to_vec(),
                exit_code: 1,
            }),
            Err(error) => {
                if cancel.is_some_and(|cancel| cancel.is_cancelled()) {
                    Err(RuntimeError::Cancelled)
                } else {
                    Err(RuntimeError::Wasi(error))
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod contract_tests {
    use std::path::{Path, PathBuf};

    use super::capability::{CapabilityGrant, FilesystemAccess, ResourceLimits};

    /// Build an absolute test root on any platform; a bare `/workspace` path is
    /// not absolute on Windows, which would make capability construction fail.
    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ferrous-{name}-{}", std::process::id()))
    }
    use super::command::{
        Actor, CommandRequest, ExecutionMode, SessionEvent, SessionState, Stream,
    };
    use super::native::{NativeBackend, NativeError};
    use super::{RuntimeError, WasiRuntime};

    #[test]
    fn empty_grant_denies_filesystem_environment_and_network() {
        let grant = CapabilityGrant::empty();

        assert!(!grant.allows_path(Path::new("/workspace/main.rs")));
        assert!(!grant.allows_environment("PATH"));
        assert!(!grant.allows_loopback_port(3000));
    }

    #[test]
    fn workspace_grant_does_not_cross_path_boundaries_or_parent_segments() {
        let project = test_root("project");
        let grant = CapabilityGrant::workspace(&project, FilesystemAccess::ReadWrite)
            .expect("absolute workspace path");

        assert!(grant.allows_path(&project.join("src/main.rs")));
        assert!(!grant.allows_path(&test_root("project-other").join("main.rs")));
        assert!(!grant.allows_path(&project.join("../secrets.txt")));
    }

    #[test]
    fn native_execution_requires_an_explicit_grant() {
        let error = CommandRequest::new(
            7,
            Actor::Agent,
            ExecutionMode::Native,
            "cargo",
            ["test"],
            "/workspace/project",
            CapabilityGrant::empty(),
        )
        .expect_err("native must be denied");

        assert!(error.to_string().contains("native execution"));
    }

    #[test]
    fn output_budget_rejects_chunks_that_would_exceed_the_limit() {
        let limits = ResourceLimits::new(4, 30).expect("valid limits");
        let mut state = SessionState::new(7, limits);

        state.accept(SessionEvent::Started).expect("session starts");
        state
            .accept(SessionEvent::Output {
                stream: Stream::Stdout,
                bytes: b"abc".to_vec(),
            })
            .expect("first chunk fits");

        let error = state
            .accept(SessionEvent::Output {
                stream: Stream::Stderr,
                bytes: b"de".to_vec(),
            })
            .expect_err("second chunk exceeds the four-byte budget");
        assert!(error.to_string().contains("output limit"));
    }

    #[test]
    fn native_backend_never_falls_back_to_ambient_execution() {
        let workspace = test_root("native-workspace");
        let grant = CapabilityGrant::workspace(&workspace, FilesystemAccess::ReadWrite)
            .expect("workspace is absolute")
            .allow_native_execution();
        let request = CommandRequest::new(
            8,
            Actor::Agent,
            ExecutionMode::Native,
            "bash",
            ["-lc", "echo unsafe"],
            &workspace,
            grant,
        )
        .expect("explicit native request is valid");

        assert_eq!(
            NativeBackend::new().start(&request),
            Err(NativeError::UnsupportedOnHost)
        );
    }

    #[test]
    fn runtime_loads_a_valid_component_and_rejects_garbage() {
        let runtime = WasiRuntime::new().expect("runtime configuration is valid");
        let component = wat::parse_str("(component)").expect("component WAT is valid");

        assert!(runtime.compile_component(&component).is_ok());
        assert!(runtime.compile_component(b"not a component").is_err());
    }

    #[test]
    fn runtime_denies_a_missing_workspace_before_guest_start() {
        let runtime = WasiRuntime::new().expect("runtime configuration is valid");
        let component = runtime
            .compile_component(&wat::parse_str("(component)").expect("component is valid"))
            .expect("component admission succeeds");
        let missing = test_root("missing-workspace-that-does-not-exist");
        let grant = CapabilityGrant::workspace(&missing, FilesystemAccess::ReadWrite)
            .expect("absolute capability path");
        let request = CommandRequest::new(
            9,
            Actor::Agent,
            ExecutionMode::Wasi,
            "tool",
            std::iter::empty::<&str>(),
            &missing,
            grant,
        )
        .expect("lexically valid request");

        assert!(matches!(
            runtime.run_wasi(&component, &request),
            Err(RuntimeError::Command(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_denies_a_symlinked_cwd_that_escapes_the_grant() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink-escape");
        let outside = test_root("symlink-escape-outside");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).expect("grant root is created");
        std::fs::create_dir_all(&outside).expect("outside directory is created");
        symlink(&outside, root.join("escape")).expect("escape symlink is created");

        let runtime = WasiRuntime::new().expect("runtime configuration is valid");
        let component = runtime
            .compile_component(&wat::parse_str("(component)").expect("component is valid"))
            .expect("component admission succeeds");
        let grant = CapabilityGrant::workspace(&root, FilesystemAccess::ReadWrite)
            .expect("absolute capability path");
        // The cwd passes the lexical check but resolves outside the grant.
        let escaped_cwd = root.join("escape");
        let request = CommandRequest::new(
            10,
            Actor::Agent,
            ExecutionMode::Wasi,
            "tool",
            std::iter::empty::<&str>(),
            &escaped_cwd,
            grant,
        )
        .expect("lexically valid request");

        assert!(matches!(
            runtime.run_wasi(&component, &request),
            Err(RuntimeError::Command(_))
        ));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn terminal_cannot_emit_output_before_start_or_after_exit() {
        let limits = ResourceLimits::new(1024, 30).expect("valid limits");
        let mut state = SessionState::new(7, limits);

        assert!(
            state
                .accept(SessionEvent::Output {
                    stream: Stream::Stdout,
                    bytes: b"early".to_vec(),
                })
                .is_err()
        );

        state.accept(SessionEvent::Started).expect("session starts");
        state
            .accept(SessionEvent::Exited { code: Some(0) })
            .expect("session exits");
        assert!(state.accept(SessionEvent::Started).is_err());
    }
}
