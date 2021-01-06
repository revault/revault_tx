use miniscript::bitcoin::consensus::encode::Error as EncodeError;

use std::{convert::From, error, fmt};

/// An error specific to the management of Revault transactions and scripts.
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// The script creation failed.
    ScriptCreation(String),
    /// The transaction creation failed.
    TransactionCreation(String),
    /// Satisfaction (PSBT signer role) of a Revault transaction input failed.
    InputSatisfaction(String),
    /// Completion (PSBT finalizer role) of the Revault transaction has failed.
    TransactionFinalisation(String),
    /// The verification of the PSBT input against libbitcoinconsensus failed.
    TransactionVerification(String),
    /// The serialization or deserialization of the transaction failed.
    TransactionSerialisation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ScriptCreation(ref e) => write!(f, "Revault script creation error: {}", e),
            Error::TransactionCreation(ref e) => {
                write!(f, "Revault transaction creation error: {}", e)
            }
            Error::InputSatisfaction(ref e) => write!(f, "Revault input satisfaction error: {}", e),
            Error::TransactionVerification(ref e) => {
                write!(f, "Revault transaction verification error: {}", e)
            }
            Error::TransactionFinalisation(ref e) => {
                write!(f, "Revault transaction finalisation error: {}", e)
            }
            Error::TransactionSerialisation(ref e) => {
                write!(f, "Revault transaction serialisation error: {}", e)
            }
        }
    }
}

impl error::Error for Error {}

impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        Self::TransactionSerialisation(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Self::TransactionSerialisation(e.to_string())
    }
}
