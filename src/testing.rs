//! Helpers shared by unit tests.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Drives a future to completion on the current thread.
///
/// The use cases only await immediately-ready futures (the repositories are
/// mocked), so a no-op waker is enough and no async runtime is needed.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}
