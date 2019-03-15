//! smbc is wrapper around `libsmbclient` from Samba project
//!
//! It provides basic `std::fs`-like API to access SMB/CIFS file shares

/// Module with smbc's Result and Error coercions
pub mod result;

pub mod parser;
/// Main API module (reexported later)
pub mod smbc;

pub use crate::{result::*, smbc::*};

pub use crate::parser::*;
