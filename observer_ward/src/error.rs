use std::io::ErrorKind;
use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
  #[error(transparent)]
  IO(#[from] std::io::Error),
  #[error(transparent)]
  Http(engine::slinger::Error),
}

impl From<engine::slinger::Error> for Error {
  fn from(value: engine::slinger::Error) -> Self {
    Error::Http(value)
  }
}

pub(crate) fn new_io_error(msg: &str) -> Error {
  Error::IO(std::io::Error::new(ErrorKind::InvalidData, msg))
}

impl Error {
  pub fn detailed_message(&self) -> String {
    match self {
      Error::IO(e) => format!("IO Error: {}", e),
      Error::Http(e) => format!("HTTP Error: {:?}", e)
    }
  }
}
