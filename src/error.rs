use derive_error as de;
use std::{ffi, io, result};

pub type SmbcResult<T> = result::Result<T, SmbcError>;

#[derive(Debug, de::Error)]
pub enum SmbcError {
    FFIError(ffi::NulError),
    IoError(io::Error),
    #[error(msg_embedded, non_std, no_from)]
    SmbcXAttrError(String),
}
