//! # Revault_tx
//!
//! Revault-specific Bitcoin scripts and transactions routines.

#![forbid(unsafe_code)]

pub use miniscript;
pub use miniscript::bitcoin;

pub mod error;
pub use error::Error;

pub mod scripts;

pub mod txins;

pub mod txouts;

pub mod transactions;
