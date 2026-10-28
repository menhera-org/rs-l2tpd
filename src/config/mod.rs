//! Configuration types: always-valid `Config` and its entries, the kernel
//! identities entries are matched by, and the conversions from merged
//! documents (spec C1–C17, L4). Filled in phase 1.

mod partial;
#[cfg(feature = "serde")]
mod serde;
mod text;
