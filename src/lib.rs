//! # Revault_tx
//!
//! Revault-specific Bitcoin scripts and transactions routines.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub use miniscript;
pub use miniscript::bitcoin;

mod error;
pub use error::Error;

pub mod scripts;

pub mod txins;

pub mod txouts;

pub mod transactions;
