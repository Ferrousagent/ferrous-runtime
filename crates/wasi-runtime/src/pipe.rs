//! Bounded, incrementally readable output pipes for live session streaming.
//!
//! [`wasmtime_wasi::p2::pipe::MemoryOutputPipe`] captures a whole guest's
//! output but offers no way to read it until the guest finishes.
//! [`StreamOutputPipe`] keeps the same
//! capped-write semantics (writing beyond capacity traps the guest, exactly as
//! the non-streaming path does) while letting a reader drain bytes as they are
//! produced, which is what the UI-boundary event stream is built on.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::p2::{OutputStream, Pollable, StreamError};

/// A bounded output pipe whose reader can drain bytes incrementally.
#[derive(Clone)]
pub struct StreamOutputPipe(Arc<StreamOutputPipeInner>);

struct StreamOutputPipeInner {
    capacity: usize,
    state: Mutex<StreamState>,
    wake: Condvar,
}

#[derive(Default)]
struct StreamState {
    buffer: Vec<u8>,
    read_pos: usize,
    eof: bool,
    /// Host-side hard close: further writes fail even if capacity remains.
    /// Used to cut a guest off once the *combined* output budget is exhausted.
    closed: bool,
}

impl StreamOutputPipe {
    /// Create a pipe that traps a guest writing beyond `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(StreamOutputPipeInner {
            capacity,
            state: Mutex::new(StreamState::default()),
            wake: Condvar::new(),
        }))
    }

    /// Wait up to `timeout` for data or end-of-stream, then drain everything
    /// written since the last call. Returns the drained bytes and whether the
    /// pipe has reached end-of-stream.
    pub fn wait_and_drain(&self, timeout: Duration) -> (Vec<u8>, bool) {
        let (guard, _) = self
            .0
            .wake
            .wait_timeout_while(
                self.0.state.lock().unwrap_or_else(PoisonError::into_inner),
                timeout,
                |state| state.read_pos == state.buffer.len() && !state.eof,
            )
            .unwrap_or_else(PoisonError::into_inner);
        let mut state = guard;
        let bytes = state.buffer[state.read_pos..].to_vec();
        state.read_pos = state.buffer.len();
        (bytes, state.eof)
    }

    /// All bytes written so far, regardless of what the reader consumed.
    pub fn contents(&self) -> Vec<u8> {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .buffer
            .clone()
    }

    /// Signal end-of-stream. Safe to call once the writer is dropped; wakes a
    /// waiting reader so it can drain the tail and exit.
    pub fn set_eof(&self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .eof = true;
        self.0.wake.notify_all();
    }

    /// Hard-close the pipe: every subsequent write fails (the guest traps)
    /// even while capacity remains. Used to enforce a combined output budget
    /// across streams. Idempotent.
    pub fn close(&self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed = true;
        self.0.wake.notify_all();
    }
}

#[async_trait]
impl OutputStream for StreamOutputPipe {
    fn write(&mut self, bytes: Bytes) -> Result<(), StreamError> {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Err(StreamError::Closed);
        }
        if bytes.len() > self.0.capacity - state.buffer.len() {
            return Err(StreamError::Trap(wasmtime::format_err!(
                "write beyond capacity of StreamOutputPipe"
            )));
        }
        state.buffer.extend_from_slice(bytes.as_ref());
        drop(state);
        self.0.wake.notify_all();
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        Ok(())
    }

    fn check_write(&mut self) -> Result<usize, StreamError> {
        let state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return Err(StreamError::Closed);
        }
        let consumed = state.buffer.len();
        if consumed < self.0.capacity {
            Ok(self.0.capacity - consumed)
        } else {
            // Full pipes are closed, mirroring MemoryOutputPipe semantics.
            Err(StreamError::Closed)
        }
    }
}

#[async_trait]
impl Pollable for StreamOutputPipe {
    async fn ready(&mut self) {}
}

impl IsTerminal for StreamOutputPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for StreamOutputPipe {
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }

    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }
}

impl tokio::io::AsyncWrite for StreamOutputPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        // `Ok(0)` from poll_write is a contract violation: consumers treat it
        // as WriteZero. A closed or full pipe reports an error instead, which
        // mirrors the sync path's trap semantics.
        if state.closed || state.buffer.len() >= self.0.capacity {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "StreamOutputPipe is closed or full",
            )));
        }
        let amt = buf.len().min(self.0.capacity - state.buffer.len());
        state.buffer.extend_from_slice(&buf[..amt]);
        drop(state);
        self.0.wake.notify_all();
        Poll::Ready(Ok(amt))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.set_eof();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn written_bytes_are_drained_incrementally() {
        let mut pipe = StreamOutputPipe::new(1024);
        pipe.write(Bytes::from_static(b"hello "))
            .expect("write succeeds");

        let (first, _) = pipe.wait_and_drain(Duration::from_millis(10));
        assert_eq!(first, b"hello ");
        let (second, _) = pipe.wait_and_drain(Duration::from_millis(10));
        assert!(second.is_empty(), "nothing new was written");
    }

    #[test]
    fn eof_is_reported_after_set_eof() {
        let pipe = StreamOutputPipe::new(1024);
        pipe.set_eof();
        let (bytes, eof) = pipe.wait_and_drain(Duration::from_millis(10));
        assert!(bytes.is_empty());
        assert!(eof);
    }

    #[test]
    fn write_beyond_capacity_is_a_trap() {
        let mut pipe = StreamOutputPipe::new(4);
        pipe.write(Bytes::from_static(b"1234"))
            .expect("fits exactly");
        assert!(matches!(
            pipe.write(Bytes::from_static(b"5")),
            Err(StreamError::Trap(_))
        ));
    }

    #[test]
    fn full_pipe_reports_closed_on_check_write() {
        let mut pipe = StreamOutputPipe::new(2);
        pipe.write(Bytes::from_static(b"ab"))
            .expect("fills the pipe");
        assert!(matches!(pipe.check_write(), Err(StreamError::Closed)));
    }

    #[test]
    fn closed_pipe_rejects_further_writes() {
        let mut pipe = StreamOutputPipe::new(1024);
        pipe.close();
        assert!(matches!(
            pipe.write(Bytes::from_static(b"x")),
            Err(StreamError::Closed)
        ));
        assert!(matches!(pipe.check_write(), Err(StreamError::Closed)));
        // A reader still drains what was written before the close.
        pipe.set_eof();
        let (bytes, eof) = pipe.wait_and_drain(Duration::from_millis(10));
        assert!(bytes.is_empty());
        assert!(eof);
    }

    #[test]
    fn close_is_idempotent_and_keeps_buffered_bytes() {
        let mut pipe = StreamOutputPipe::new(1024);
        pipe.write(Bytes::from_static(b"abc"))
            .expect("write succeeds");
        pipe.close();
        pipe.close();
        assert!(matches!(
            pipe.write(Bytes::from_static(b"d")),
            Err(StreamError::Closed)
        ));
        assert_eq!(pipe.contents(), b"abc");
    }

    #[test]
    fn async_write_errors_instead_of_reporting_zero() {
        use std::pin::pin;

        let mut pipe = StreamOutputPipe::new(2);
        pipe.write(Bytes::from_static(b"ab"))
            .expect("fills the pipe");
        let mut pinned = pin!(pipe);
        let result = tokio::io::AsyncWrite::poll_write(
            pinned.as_mut(),
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
            b"c",
        );
        assert!(
            matches!(result, Poll::Ready(Err(_))),
            "full pipe must error, got {result:?}"
        );
    }

    #[test]
    fn contents_returns_everything_written() {
        let mut pipe = StreamOutputPipe::new(1024);
        pipe.write(Bytes::from_static(b"ab"))
            .expect("write succeeds");
        let _ = pipe.wait_and_drain(Duration::from_millis(10));
        pipe.write(Bytes::from_static(b"cd"))
            .expect("write succeeds");
        assert_eq!(pipe.contents(), b"abcd");
    }
}
