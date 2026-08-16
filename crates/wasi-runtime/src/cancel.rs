//! Cooperative cancellation for running Ferrous sessions.
//!
//! A [`CancelHandle`] is a one-shot signal shared between a broker and a running
//! backend. Setting it interrupts the guest at its next epoch check; it is never
//! reset, so a cancelled session stays cancelled.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// One-shot cancellation signal shared between a broker and a running backend.
#[derive(Clone, Debug, Default)]
pub struct CancelHandle(Arc<AtomicBool>);

impl CancelHandle {
    /// Create a handle that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. Safe to call more than once.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fresh_handle_is_not_cancelled() {
        let handle = CancelHandle::new();
        assert!(!handle.is_cancelled());
    }

    #[test]
    fn cancel_flips_the_flag_and_is_idempotent() {
        let handle = CancelHandle::new();
        handle.cancel();
        assert!(handle.is_cancelled());
        handle.cancel();
        assert!(handle.is_cancelled());
    }

    #[test]
    fn cloned_handles_share_the_signal() {
        let handle = CancelHandle::new();
        let clone = handle.clone();
        handle.cancel();
        assert!(clone.is_cancelled());
    }
}
