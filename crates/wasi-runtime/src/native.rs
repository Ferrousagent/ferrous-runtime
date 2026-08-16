//! Native terminal boundary.
//!
//! This module intentionally does not spawn a process yet. The important Phase 1
//! behavior is that native requests have a named backend and return `unsupported`
//! rather than silently executing with ambient authority.

use thiserror::Error;

use crate::command::{CommandRequest, ExecutionMode};

/// Native execution backend selected by policy.
#[derive(Debug, Default)]
pub struct NativeBackend;

impl NativeBackend {
    /// Create the host-native backend boundary.
    pub const fn new() -> Self {
        Self
    }

    /// Start a native request when a platform adapter is available.
    ///
    /// Phase 1 deliberately returns [`NativeError::UnsupportedOnHost`] on every host
    /// until the PTY/ConPTY process policy is implemented and tested.
    pub fn start(&self, request: &CommandRequest) -> Result<(), NativeError> {
        if request.mode != ExecutionMode::Native {
            return Err(NativeError::WrongMode);
        }
        if !request.grant.allows_native_execution() {
            return Err(NativeError::NativeNotGranted);
        }
        Err(NativeError::UnsupportedOnHost)
    }
}

/// Fail-closed errors from the native backend boundary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum NativeError {
    /// The request selected a different backend.
    #[error("native backend received a non-native request")]
    WrongMode,
    /// Native execution was not granted.
    #[error("native execution was not granted")]
    NativeNotGranted,
    /// No tested platform sandbox adapter is available yet.
    #[error("native execution is unsupported on this host")]
    UnsupportedOnHost,
}
