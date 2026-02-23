use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
    Regex(regex::Error),
    InvalidInput(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {}", e),
            AppError::Utf8(e) => write!(f, "UTF-8 error: {}", e),
            AppError::Regex(e) => write!(f, "Regex error: {}", e),
            AppError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<std::str::Utf8Error> for AppError {
    fn from(e: std::str::Utf8Error) -> Self {
        AppError::Utf8(e)
    }
}

impl From<regex::Error> for AppError {
    fn from(e: regex::Error) -> Self {
        AppError::Regex(e)
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
