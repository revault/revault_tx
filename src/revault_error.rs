use std::{error, fmt};

#[derive(Debug)]
pub enum RevaultError {
    TransactionCreation(String),
}

impl fmt::Display for RevaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RevaultError::TransactionCreation(ref e) => {
                write!(f, "Revault transaction creation error: {}", e)
            }
        }
    }
}

impl error::Error for RevaultError {}
