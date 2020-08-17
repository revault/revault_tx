use std::{error, fmt};

#[derive(PartialEq, Eq, Debug)]
pub enum RevaultError {
    TransactionCreation(String),
    ScriptCreation(String),
    Signature(String),
    InputSatisfaction(String),
    TransactionVerification(String),
}

impl fmt::Display for RevaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RevaultError::TransactionCreation(ref e) => {
                write!(f, "Revault transaction creation error: {}", e)
            }
            RevaultError::ScriptCreation(ref e) => {
                write!(f, "Revault script creation error: {}", e)
            }
            RevaultError::Signature(ref e) => {
                write!(f, "Revault transaction signature error: {}", e)
            }
            RevaultError::InputSatisfaction(ref e) => {
                write!(f, "Revault input satisfaction error: {}", e)
            }
            RevaultError::TransactionVerification(ref e) => {
                write!(f, "Revault transaction verification error: {}", e)
            }
        }
    }
}

impl error::Error for RevaultError {}
