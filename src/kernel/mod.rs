//! The one boundary to the host: the `Kernel` trait every reconciler
//! operation goes through, its real implementation and its fake
//! (`docs/architecture.md`, "The kernel boundary"). Filled in phase 2.

#[cfg(any(test, feature = "fake-kernel"))]
pub mod fake;
pub mod linux;
