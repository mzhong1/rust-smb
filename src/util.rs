// smbc is library wrapping libsmbclient from Samba project
// Copyright (c) 2016 Konstantin Gribov
//
// This file is part of smbc.
//
// smbc is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// smbc is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with smbc. If not, see <http://www.gnu.org/licenses/>.

use libc::c_int;
use std::io;
/// try! get smbc function or return io::Error(EINVAL)
macro_rules! try_ufnrc {
    ($e:ident <- $s:expr) => {
        r#try!($e($s).ok_or(std::io::Error::from_raw_os_error(EINVAL as i32)))
    };
}

#[inline(always)]
/// Ok(ptr) for non-null ptr or Err(last_os_error) otherwise
pub fn result_from_ptr_mut<T>(ptr: *mut T) -> io::Result<*mut T> {
    if ptr.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

#[inline(always)]
/// to io::Result with Err(last_os_error) if t == -1
pub fn to_result_with_le<T: Eq + From<i8>>(t: T) -> io::Result<T> {
    to_result_with_error(t, io::Error::last_os_error())
}

#[inline(always)]
/// to io::Result with Err(from_raw_os_error(errno)) if t == -1
pub fn to_result_with_errno<T: Eq + From<i8>>(t: T, errno: c_int) -> io::Result<T> {
    to_result_with_error(t, io::Error::from_raw_os_error(errno as i32))
}

#[inline(always)]
fn to_result_with_error<T: Eq + From<i8>>(t: T, err: io::Error) -> io::Result<T> {
    if t == T::from(-1) {
        Err(err)
    } else {
        Ok(t)
    }
}
