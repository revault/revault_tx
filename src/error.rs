//! Errors related to Revault transactions and Scripts management

use crate::transactions::INSANE_FEES;

use bitcoinconsensus::Error as LibConsensusError;
use miniscript::{
    bitcoin::consensus::encode::Error as EncodeError, policy::compiler::CompilerError,
};

use std::{convert::From, error, fmt};

/// Error when creating a Revault Bitcoin Script
#[derive(PartialEq, Eq, Debug)]
pub enum ScriptCreationError {
    /// Invalid number of keys, threshold, or timelock
    BadParameters,
    /// Miniscript policy compilation error
    PolicyCompilation(CompilerError),
}

impl fmt::Display for ScriptCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadParameters => write!(f, "Bad parameters"),
            Self::PolicyCompilation(e) => write!(f, "Policy compilation error: '{}'", e),
        }
    }
}

impl From<CompilerError> for ScriptCreationError {
    fn from(e: CompilerError) -> Self {
        Self::PolicyCompilation(e)
    }
}

impl error::Error for ScriptCreationError {}

/// Error when creating a Revault Bitcoin transaction
#[derive(PartialEq, Eq, Debug)]
pub enum TransactionCreationError {
    /// Fees would be higher than [INSANE_FEES] (not checked for revocation transactions)
    InsaneFees,
    /// Would spend or create a dust output
    Dust,
}

impl fmt::Display for TransactionCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InsaneFees => write!(f, "Fees larger than {} sats", INSANE_FEES),
            Self::Dust => write!(f, "Spending or creating a dust output"),
        }
    }
}

impl error::Error for TransactionCreationError {}

/// Error when satisfying a Revault Bitcoin transaction input
#[derive(PartialEq, Eq, Debug)]
pub enum InputSatisfactionError {
    /// Index is out of bounds of the inputs list
    OutOfBounds,
    /// Provided signature's sighash byte is different from PSBT input's type
    UnexpectedSighashType,
}

impl fmt::Display for InputSatisfactionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "Index out of bounds of inputs list"),
            Self::UnexpectedSighashType => {
                write!(f, "Signature's sighash byte differ from PSBT input's type")
            }
        }
    }
}

impl error::Error for InputSatisfactionError {}

/// An error specific to the management of Revault transactions and scripts.
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// Error when creating a Revault Bitcoin Script
    ScriptCreation(ScriptCreationError),
    /// The transaction creation failed.
    TransactionCreation(TransactionCreationError),
    /// Satisfaction (PSBT signer role) of a Revault transaction input failed.
    InputSatisfaction(InputSatisfactionError),
    // FIXME: have upstream(s) derive PartialEq on Errors?
    /// Completion (PSBT finalizer role) of the Revault transaction failed.
    TransactionFinalisation(String),
    /// The verification of the PSBT input against libbitcoinconsensus failed.
    TransactionVerification(LibConsensusError),
    // FIXME: have upstream(s) derive PartialEq on Errors?
    /// The serialization or deserialization of the transaction failed.
    TransactionSerialisation(String),
}

impl From<ScriptCreationError> for Error {
    fn from(e: ScriptCreationError) -> Self {
        Self::ScriptCreation(e)
    }
}

impl From<TransactionCreationError> for Error {
    fn from(e: TransactionCreationError) -> Self {
        Self::TransactionCreation(e)
    }
}

impl From<InputSatisfactionError> for Error {
    fn from(e: InputSatisfactionError) -> Self {
        Self::InputSatisfaction(e)
    }
}

impl From<LibConsensusError> for Error {
    fn from(e: LibConsensusError) -> Self {
        Self::TransactionVerification(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ScriptCreation(ref e) => write!(f, "Revault script creation error: '{}'", e),
            Error::TransactionCreation(ref e) => {
                write!(f, "Revault transaction creation error: '{}'", e)
            }
            Error::InputSatisfaction(ref e) => {
                write!(f, "Revault input satisfaction error: '{}'", e)
            }
            Error::TransactionVerification(ref e) => {
                write!(f, "Revault transaction verification error: '{:?}'", e)
            }
            Error::TransactionFinalisation(ref e) => {
                write!(f, "Revault transaction finalisation error: '{}'", e)
            }
            Error::TransactionSerialisation(ref e) => {
                write!(f, "Revault transaction serialisation error: '{}'", e)
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
