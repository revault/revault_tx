//! Revault errors
//!
//! Errors related to the management of Revault transactions and scripts.

use std::{error, fmt};

/// An error specific to the management of Revault transactions and scripts.
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// The transaction creation failed.
    TransactionCreation(String),
    /// The script creation failed.
    ScriptCreation(String),
    /// Signature-related errors (sighash, ..).
    Signature(String),
    /// Miniscript satisfaction of a Revault transaction input failed.
    InputSatisfaction(String),
    /// The verification of the transaction against libbitcoinconsensus failed.
    TransactionVerification(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::TransactionCreation(ref e) => {
                write!(f, "Revault transaction creation error: {}", e)
            }
            Error::ScriptCreation(ref e) => write!(f, "Revault script creation error: {}", e),
            Error::Signature(ref e) => write!(f, "Revault transaction signature error: {}", e),
            Error::InputSatisfaction(ref e) => write!(f, "Revault input satisfaction error: {}", e),
            Error::TransactionVerification(ref e) => {
                write!(f, "Revault transaction verification error: {}", e)
            }
        }
    }
}

impl error::Error for Error {}
