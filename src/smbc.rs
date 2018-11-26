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

//! `smbc` is wrapper library around `libsmbclient` from Samba project.

// imports {{{1

use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::io::{Error, ErrorKind};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::zeroed;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;

use chrono::*;
use libc::{c_char, c_int, mode_t, off_t, EINVAL};
use nix::fcntl::OFlag;
use result::Result;
use smbclient_sys::*;
use util::*;
// 1}}}

const SMBC_FALSE: smbc_bool = 0;
const SMBC_TRUE: smbc_bool = 1;

struct SmbcPtr(*mut SMBCCTX);
impl Drop for SmbcPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            trace!(target: "smbc", "closing smbcontext");
            unsafe {
                smbc_free_context(self.0, 1 as c_int);
            }
        }
    }
}

fn check_mut_ptr<T>(ptr: *mut T) -> io::Result<*mut T> {
    if ptr.is_null() {
        Err(Error::last_os_error())
    } else {
        Ok(ptr)
    }
}

#[derive(Clone)]
pub struct Smbc {
    context: Rc<SmbcPtr>,
}

bitflags! {
    pub struct Mode: mode_t {
        /// Extract file code from mode value
        const S_IFMT = 0xF000;
        /// Socket
        const S_IFSOCK = 0xC000;
        /// Sym Link
        const S_IFLNK = 0xA000;
        /// Regular
        const S_IFREG = 0x8000;
        /// Block Device
        const S_IFBLK = 0x6000;
        /// Dir
        const S_IFDIR = 0x4000;
        /// Character Device
        const S_IFCHR = 0x2000;
        /// File IO
        const S_IFIFO = 0x1000;

        /// Set user ID on execution
        const S_ISUID = 0x00800;
        /// Set group ID on execution
        const S_ISGID = 0x00400;
        /// Save swapped text (not defined in POSIX)
        const S_ISVTX = 0x00200;

        /// Read, Write, Execute permission for owner on a file.
        const S_IRWXU = 0x001C0;
        /// Read permission for owner
        const S_IRUSR = 0x00100;
        /// Write permission for owner
        const S_IWUSR = 0x00080;
        /// Execute permission for owner on a file. Or lookup
        /// (search) permission for owner in directory
        const S_IXUSR = 0x00040;


        /// Read Write Execute permission for group
        const S_IRWXG = 0x00038;
        /// Read permission for group
        const S_IRGRP = 0x00020;
        /// Write permission for group
        const S_IWGRP = 0x00010;
        /// Execute permission for group on a file. Or lookup
        /// (search) permission for group in directory
        const S_IXGRP = 0x00008;

        /// Read Write Execute permission for others
        const S_IRWXO = 0x00007;
        /// Read permission for others
        const S_IROTH = 0x00004;
        /// Write permission for others
        const S_IWOTH = 0x00002;
        /// Execute permission for others on a file. Or lookup
        /// (search) permission for others in directory
        const S_IXOTH = 0x00001;
    }
}

bitflags!{
    pub struct XAttrFlags :i32 {
        //zeroed
        const SMBC_XATTR_FLAG_NONE = 0x0;
        //create new attribute
        const SMBC_XATTR_FLAG_CREATE = 0x1;
        //replace attribute
        const SMBC_XATTR_FLAG_REPLACE = 0x2;
    }
}

bitflags!{
    pub struct XAttrMask : i32 {
        const NONE = 0x00000000;
        const R = 0x00120089;
        const W = 0x00120116;
        const X = 0x001200a0;
        const D = 0x00010000;
        const P = 0x00040000;
        const O = 0x00080000;
        const N = 0;
        const READ = 0x001200a9;
        const CHANGE = 0x001301bf;
        const FULL = 0x001f01ff;
    }
}

bitflags!{
    pub struct DosMode : i32 {
        const READONLY = 0x01;
        const HIDDEN = 0x02;
        const SYSTEM = 0x04; //OS use
        const VOLUME_ID = 0x08;
        const DIRECTORY = 0x10;
        const ARCHIVE = 0x20;
        const DEVICE = 0x40; //reserved for system use
        const NORMAL = 0x80; //valid only by itself
        const TEMPORARY = 0x100;
        const SPARSE_FILE = 0x200; //sparse file
        const REPARSE_POINT = 0x400; //has sym link
        const COMPRESSED = 0x800;
        const OFFLINE = 0x1000; //data moved offline storage
         const NOT_CONTENT_INDEXED = 0x2000;
        const ENCRYPTED = 0x4000; //Encrypted file/dir
        const INTEGRITY_STREAM = 0x8000; //dir or data stream conf with integrity (ReFS vol only)
    }
}

#[derive(Debug, Clone)]
pub enum SmbcType {
    WORKGROUP = 1,
    SERVER = 2,
    FILESHARE = 3,
    PRINTERSHARE = 4,
    COMMSSHARE = 5,
    IPCSHARE = 6,
    DIR = 7,
    FILE = 8,
    LINK = 9,
}

impl SmbcType {
    fn from(t: u32) -> io::Result<SmbcType> {
        match t {
            1 => Ok(SmbcType::WORKGROUP),
            2 => Ok(SmbcType::SERVER),
            3 => Ok(SmbcType::FILESHARE),
            4 => Ok(SmbcType::PRINTERSHARE),
            5 => Ok(SmbcType::COMMSSHARE),
            6 => Ok(SmbcType::IPCSHARE),
            7 => Ok(SmbcType::DIR),
            8 => Ok(SmbcType::FILE),
            9 => Ok(SmbcType::LINK),
            _ => Err(io::Error::new(
                ErrorKind::InvalidData,
                "Unknown file type: ",
            )),
        }
    }
}
/*
"system.nt_sec_desc.-----"
"system.dos_attr.-----"
"system.*"
"system.*+"
"system.+"
"system.nt_sec_desc.revision"
"system.nt_sec_desc.owner"
"system.nt_sec_desc.owner+"
"system.nt_sec_desc.group"
system.nt_sec_desc.group+
system.nt_sec_desc.acl.*
system.nt_sec_desc.*
system.nt_sec_desc.*+

system.dos_attr.*
system.dos_attr.mode
system.dos_attr.c_time
system.dos_attr.a_time
system.dos_attr.m_time
*/

pub enum SmbcXAttr {
    All,
    AllPlus,
    AllExclude(Vec<SmbcExclude>),     //get xattr only
    AllExcludePlus(Vec<SmbcExclude>), //get xattr only
    DosAttr(SmbcDosAttr),
    AclAttr(SmbcAclAttr),
    //TestAll,
}

impl fmt::Display for SmbcXAttr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcXAttr::All => write!(f, "system.*"),
            SmbcXAttr::AllPlus => write!(f, "system.*+"),
            SmbcXAttr::AllExclude(s) => write!(f, "system.*!{}", separated(s, "!")),
            SmbcXAttr::AllExcludePlus(s) => write!(f, "system.*+!{}", separated(s, "!")),
            SmbcXAttr::DosAttr(d) => d.fmt(f),
            SmbcXAttr::AclAttr(a) => a.fmt(f),
            //SmbcXattr::TestAll => write!(f, "user.*"),
        }
    }
}

#[derive(Debug)]
pub enum SmbcDosAttr {
    All,
    AllExclude(Vec<SmbcExclude>),
    Atime,
    Ctime,
    Mode,
    Mtime,
    Inode,
    Size,
}

impl fmt::Display for SmbcDosAttr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcDosAttr::All => write!(f, "system.dos_attr.*"),
            SmbcDosAttr::AllExclude(s) => write!(f, "system.dos_attr.*!{}", separated(s, "!")),
            SmbcDosAttr::Atime => write!(f, "system.dos_attr.a_time"),
            SmbcDosAttr::Ctime => write!(f, "system.dos_attr.c_time"),
            SmbcDosAttr::Mode => write!(f, "system.dos_attr.mode"),
            SmbcDosAttr::Mtime => write!(f, "system.dos_attr.m_time"),
            SmbcDosAttr::Inode => write!(f, "system.dos_attr.inode"),
            SmbcDosAttr::Size => write!(f, "system.dos_attr.size"),
        }
    }
}

#[derive(Debug)]
pub enum SmbcAclAttr {
    Acl(ACE),        //remove use only
    AclPlus(String), //remove use only
    AclAll,
    AclAllPlus,
    AclNone,         //set only use
    AclNonePlus,     //set only use
    AclSid(Sid),     //for get use only
    AclSidPlus(Sid), //for get use only
    All,
    AllPlus,
    AllExclude(Vec<SmbcExclude>),
    AllExcludePlus(Vec<SmbcExclude>),
    Group,
    GroupPlus,
    Revision,
    Owner,
    OwnerPlus,
}

impl fmt::Display for SmbcAclAttr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcAclAttr::Acl(s) => write!(f, "system.nt_sec_desc.acl{}", format!(":{}", s)),
            SmbcAclAttr::AclAll => write!(f, "system.nt_sec_desc.acl.*"),
            SmbcAclAttr::AclAllPlus => write!(f, "system.nt_sec_desc.acl.*+"),
            SmbcAclAttr::AclNone => write!(f, "system.nt_sec_desc.acl"),
            SmbcAclAttr::AclNonePlus => write!(f, "system.nt_sec_desc.acl+"),
            SmbcAclAttr::AclPlus(s) => write!(f, "system.nt_sec_desc.acl+{}", format!(":{}", s)),
            SmbcAclAttr::AclSid(s) => write!(f, "system.nt_sec_desc.acl{}", format!("{}", s)),
            SmbcAclAttr::AclSidPlus(s) => write!(f, "system.nt_sec_desc.acl+{}", format!("{}", s)),
            SmbcAclAttr::All => write!(f, "system.nt_sec_desc.*"),
            SmbcAclAttr::AllPlus => write!(f, "system.nt_sec_desc.*+"),
            SmbcAclAttr::AllExclude(s) => write!(f, "system.nt_sec_desc.*!{}", separated(s, "!")),
            SmbcAclAttr::AllExcludePlus(s) => {
                write!(f, "system.nt_sec_desc.*!{}", separated(s, "!"))
            }
            SmbcAclAttr::Group => write!(f, "system.nt_sec_desc.group"),
            SmbcAclAttr::GroupPlus => write!(f, "system.nt_sec_desc.group+"),
            SmbcAclAttr::Revision => write!(f, "system.nt_sec_desc.revision"),
            SmbcAclAttr::Owner => write!(f, "system.nt_sec_desc.owner"),
            SmbcAclAttr::OwnerPlus => write!(f, "system.nt_sec_desc.owner+"),
        }
    }
}

//Values for input change values
//REVISION:{}
//OWNER:{}
//OWNER+:{}
//GROUP:{}
//GROUP:+

#[derive(Debug, Clone)]
pub enum SmbcAclValue {
    Acl(ACE),
    AclPlus(ACE),
    Group(Sid),
    GroupPlus(String),
    Owner(Sid),
    OwnerPlus(String),
    Revision(u64),
}

impl fmt::Display for SmbcAclValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcAclValue::Acl(s) => write!(f, "ACL:{}", format!("{}", s)),
            SmbcAclValue::AclPlus(s) => write!(f, "ACL:{}", format!("{}", s)),
            SmbcAclValue::Group(s) => write!(f, "GROUP:{}", format!("{}", s)),
            SmbcAclValue::GroupPlus(s) => write!(f, "GROUP+:{}", s),
            SmbcAclValue::Revision(i) => write!(f, "REVISION:{}", i),
            SmbcAclValue::Owner(s) => write!(f, "OWNER:{}", format!("{}", s)),
            SmbcAclValue::OwnerPlus(s) => write!(f, "OWNER+:{}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AceAtype {
    ALLOWED,
    DENIED,
}

bitflags!{
    pub struct AceFlag : i32{
        const NONE = 0;
        const SEC_ACE_FLAG_OBJECT_INHERIT = 0x1;
        const SEC_ACE_FLAG_CONTAINER_INHERIT = 0x2;
        const SEC_ACE_FLAG_NO_PROPAGATE_INHERIT = 0x4;
        const SEC_ACE_FLAG_INHERIT_ONLY = 0x8;
    }
}

#[derive(Debug, Clone)]
pub struct Sid(pub Vec<u64>);
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut dash_separated = String::new();
        dash_separated.push_str("S-1-");
        let s = separated(&self.0, "-");
        dash_separated.push_str(&s);
        write!(f, "{}", dash_separated)
    }
}

#[derive(Debug, Clone)]
pub enum ACE {
    Numeric(Sid, AceAtype, AceFlag, XAttrMask),
    Named(String, AceAtype, AceFlag, XAttrMask),
}

impl fmt::Display for ACE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ACE::Numeric(s, atype, flags, mask) => match atype {
                ALLOWED => write!(
                    f,
                    "{}:{}/{:x}/{}",
                    format!("{}", s),
                    0,
                    flags.bits(),
                    mask.bits()
                ),
                DENIED => write!(
                    f,
                    "{}:{}/{:x}/{}",
                    format!("{}", s),
                    1,
                    flags.bits(),
                    mask.bits()
                ),
            },
            ACE::Named(sid, atype, flags, mask) => match atype {
                ALLOWED => write!(
                    f,
                    "{}:{}/{:x}/0x{:x}",
                    sid,
                    "ALLOWED",
                    flags.bits(),
                    mask.bits()
                ),
                DENIED => write!(
                    f,
                    "{}:{}/{:x}/0x{:x}",
                    sid,
                    "DENIED",
                    flags.bits(),
                    mask.bits()
                ),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum SmbcDosValue {
    MODE(DosMode),
    ATime(u64),
    CTime(u64),
    MTime(u64),
}

impl fmt::Display for SmbcDosValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcDosValue::MODE(m) => write!(f, "MODE:{}", m.bits()),
            SmbcDosValue::ATime(m) => write!(f, "A_TIME:{}", m),
            SmbcDosValue::CTime(m) => write!(f, "C_TIME:{}", m),
            SmbcDosValue::MTime(m) => write!(f, "M_TIME:{}", m),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SmbcXAttrValue {
    Ace(ACE), //acl
    AclAll(Vec<SmbcAclValue>),
    AcePlus(ACE), //acl+
    DosAll(Vec<SmbcDosValue>),
    Sid(Sid),        //owner, group
    SidPlus(String), //owner, group+
    Unsigned(u64),   //revision, a_time, c_time, m_time, inode
    Mode(DosMode),   //mode
    Signed(i64),     //size
}

pub fn separated<D: fmt::Display>(iter: &Vec<D>, delimiter: &str) -> String {
    let mut delim_separated = String::new();
    for num in &iter[0..iter.len() - 1] {
        delim_separated.push_str(&format!("{}", num));
        delim_separated.push_str(delimiter);
    }
    delim_separated.push_str(&iter[iter.len() - 1].to_string());
    delim_separated
}

impl fmt::Display for SmbcXAttrValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcXAttrValue::Ace(s) => s.fmt(f),
            SmbcXAttrValue::AcePlus(s) => s.fmt(f),
            SmbcXAttrValue::AclAll(s) => {
                let mut comma_separated = separated(s, "\n");
                write!(f, "{}", comma_separated)
            }
            SmbcXAttrValue::DosAll(s) => {
                let mut comma_separated = separated(s, "\t");
                write!(f, "{}", comma_separated)
            }
            SmbcXAttrValue::Sid(s) => s.fmt(f),
            SmbcXAttrValue::SidPlus(s) => write!(f, "{}", s),
            SmbcXAttrValue::Unsigned(s) => write!(f, "{}", s),
            SmbcXAttrValue::Mode(m) => write!(f, "{:x}", m.bits()),
            SmbcXAttrValue::Signed(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SmbcExclude {
    Rev,
    Own,
    Grp,
    Acl,
    Mod,
    Siz,
    Ctm,
    Atm,
    Mtm,
    Ino,
}

impl fmt::Display for SmbcExclude {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SmbcExclude::Rev => write!(f, "nt_sec_desc.revision"),
            SmbcExclude::Own => write!(f, "nt_sec_desc.owner"),
            SmbcExclude::Grp => write!(f, "nt_sec_desc.group"),
            SmbcExclude::Acl => write!(f, "nt_sec_desc.acl"),
            SmbcExclude::Mod => write!(f, "dos_attr.mode"),
            SmbcExclude::Siz => write!(f, "dos_attr.size"),
            SmbcExclude::Ctm => write!(f, "dos_attr.c_time"),
            SmbcExclude::Atm => write!(f, "dos_attr.a_time"),
            SmbcExclude::Mtm => write!(f, "dos_attr.m_time"),
            SmbcExclude::Ino => write!(f, "dos_attr.inode"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmbcDirEntry {
    pub s_type: SmbcType,
    pub comment: String,
    pub path: PathBuf,
}

#[derive(Clone)]
pub struct SmbcDirectory {
    smbc: Rc<SmbcPtr>,
    handle: *mut SMBCFILE,
}

impl Drop for SmbcDirectory {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            trace!(target: "smbc", "closing smbc file");
            unsafe {
                smbc_getFunctionClosedir(self.smbc.0).map(|f| f(self.smbc.0, self.handle));
            }
        }
    }
}

#[derive(Clone)]
pub struct SmbcFile {
    smbc: Rc<SmbcPtr>,
    fd: *mut SMBCFILE,
}

impl Drop for SmbcFile {
    fn drop(&mut self) {
        if !self.fd.is_null() {
            unsafe {
                smbc_getFunctionClose(self.smbc.0).map(|f| f(self.smbc.0, self.fd));
            }
        }
    }
}

impl Smbc {
    pub fn new(
        auth_fn: &extern "C" fn(
            ctx: *mut SMBCCTX,
            srv: *const c_char,
            shr: *const c_char,
            wg: *mut c_char,
            wglen: c_int,
            un: *mut c_char,
            unlen: c_int,
            pw: *mut c_char,
            pwlen: c_int,
        ) -> (),
        init_fn: &extern "C" fn(
            srv: *const c_char,
            shr: *const c_char,
            wg: *mut c_char,
            wglen: c_int,
            un: *mut c_char,
            unlen: c_int,
            pw: *mut c_char,
            pwlen: c_int,
        ) -> (),
    ) -> Result<Self> {
        let mut smbc = Smbc {
            context: Rc::new(SmbcPtr(ptr::null_mut())),
        };
        unsafe {
            let ctx = result_from_ptr_mut(smbc_new_context())?;
            smbc_setFunctionAuthDataWithContext(ctx, Some(*auth_fn));
            smbc_setOptionUserData(ctx, auth_fn as *const _ as *mut c_void);
            //smbc_setOptionUseKerberos(ctx, 1);
            //smbc_setOptionFallbackAfterKerberos(ctx, 1);
            let ptr: *mut SMBCCTX = match result_from_ptr_mut(smbc_init_context(ctx)) {
                Ok(p) => p,
                // On Err here you need to call smbc_free
                Err(e) => {
                    trace!("smbc_init failed {:?}", e);
                    smbc_free_context(ctx, 1 as c_int);
                    ptr::null_mut()
                }
            };
            smbc_set_context(ptr);
            //smbc_init(Some(*init_fn), 0);
            smbc.context = Rc::new(SmbcPtr(ptr));
        }
        trace!("ctx workgroup {:?}", unsafe {
            CString::from_raw((*smbc.context.0).workgroup)
        });
        trace!("ctx user {:?}", unsafe {
            CString::from_raw((*smbc.context.0).user)
        });
        trace!("ctx netbios {:?}", unsafe {
            CString::from_raw((*smbc.context.0).netbios_name)
        });
        Ok(smbc)
    }
    ///
    /// Create a file on an SMB server.
    ///
    /// Same as calling smbc_open() with flags = O_CREAT|O_WRONLY|O_TRUNC
    ///
    /// @param furl      The smb url of the file to be created
    ///
    /// @param mode      NOTE: mode does not do anything for file permissions.  
    ///
    /// @return          SmbcFile, Error with errno set:
    ///                  - ENOMEM  Out of memory
    ///                  - EINVAL if an invalid parameter passed, like no
    ///                  file, or smbc_init not called.
    ///                  - EEXIST  pathname already exists and O_CREAT and
    ///                  O_EXCL were used.
    ///                  - EISDIR  pathname  refers  to  a  directory  and
    ///                   the access requested involved writing.
    ///                   - EACCES  The requested access to the file is not
    ///                   allowed
    ///                   - ENOENT  A directory component in pathname does
    ///                   not exist.
    ///                   - ENODEV The requested share does not exist.
    ///
    pub fn create(&mut self, path: &Path, mode: Mode) -> Result<SmbcFile> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        trace!("Attempting to retrieve create function");
        let creat_fn = try_ufnrc!(smbc_getFunctionCreat <- self.context);
        trace!("Sucessfully retrieved create function, attempting to apply function");
        unsafe {
            let fd = result_from_ptr_mut(creat_fn(
                self.context.0,
                path.as_ptr(),
                mode.bits() as mode_t,
            ))?;
            trace!("Returned value is {:?}", fd);
            if (fd as i64) < 0 {
                trace!("Error: neg fd");
            }
            Ok(SmbcFile {
                smbc: Rc::clone(&self.context),
                fd: fd,
            })
        }
    }

    /// Chmod
    /// chmod changes the DOS attributes of the input filepath
    /// NOTE: chmod only works if, in the smb.conf file,
    /// store dos mode = yes and vfs objects = yes,
    /// or store dos mode = yes,
    /// or neither of those attributes are set in the config file.
    /// You may only change/add/modify the following attributes:
    /// R - ReadOnly
    /// A - Archive
    /// S - System
    /// H - Hidden
    /// (Note that, if none of those are set, you will have either N
    /// for normal file, or D for directory)
    /// The four above attributes can only be modified if you:
    /// Have an appropriate mask in your config, and their
    /// respective map <attribute> = yes
    /// R => map readonly = yes
    /// A => map archive = yes
    /// S => map system = yes
    /// H => map Hidden = yes
    ///
    /// For more details on how chmod works, please go to:
    /// https://ftp.samba.org/pub/pub/unpacked/SOC/2005/SAMBA_3_0/source/libsmb/libsmbclient.c
    ///
    pub fn chmod(&self, path: &Path, mode: Mode) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        trace!("Attempting to retrieve chmod function");
        let chmod_fn = try_ufnrc!(smbc_getFunctionChmod <- self.context);
        trace!("Sucessfully retrieved chmod function, attempting to apply function");
        unsafe {
            to_result_with_le(chmod_fn(
                self.context.0,
                path.as_ptr(),
                mode.bits() as mode_t,
            ))?;
        }
        trace!("Chmod_fn ran");
        Ok(())
    }
    ///@ingroup file
    /// Open a file on an SMB server.
    ///
    /// @param path      The smb url of the file to be opened.
    ///
    /// @param flags     Is one of O_RDONLY, O_WRONLY or O_RDWR which
    ///                  request opening  the  file  read-only,write-only
    ///                  or read/write. flags may also be bitwise-or'd with
    ///                  one or  more of  the following:
    ///                  O_CREAT - If the file does not exist it will be
    ///                  created.
    ///                  O_EXCL - When  used with O_CREAT, if the file
    ///                  already exists it is an error and the open will
    ///                  fail.
    ///                  O_TRUNC - If the file already exists it will be
    ///                  truncated.
    ///                  O_APPEND The  file  is  opened  in  append mode
    ///
    /// @param mode      mode specifies the permissions to use if a new
    ///                  file is created.  It  is  modified  by  the
    ///                  process's umask in the usual way: the permissions
    ///                  of the created file are (mode & ~umask)
    ///
    ///                  Not currently use, but there for future use.
    ///                  We will map this to SYSTEM, HIDDEN, etc bits
    ///                  that reverses the mapping that smbc_fstat does.
    ///
    /// @return          Valid file handle, < 0 on error with errno set:
    ///                  - ENOMEM  Out of memory
    ///                  - EINVAL if an invalid parameter passed, like no
    ///                  file, or smbc_init not called.
    ///                  - EEXIST  pathname already exists and O_CREAT and
    ///                  O_EXCL were used.
    ///                  - EISDIR  pathname  refers  to  a  directory  and
    ///                  the access requested involved writing.
    ///                  - EACCES  The requested access to the file is not
    ///                  allowed
    ///                  - ENODEV The requested share does not exist
    ///                  - ENOTDIR A file on the path is not a directory
    ///                  - ENOENT  A directory component in pathname does
    ///                  not exist.
    ///
    /// @note            This call uses an underlying routine that may create
    ///                  a new connection to the server specified in the URL.
    ///                  If the credentials supplied in the URL, or via the
    ///                  auth_fn in the smbc_init call, fail, this call will
    ///                  try again with an empty username and password. This
    ///                  often gets mapped to the guest account on some machines.
    ///
    ///                  Mode doesn't DO anything for file permissions.
    ///                  the mode variable is never used internally,
    ///                  so the file is always opened with default, or
    ///                  it's own permissions.  It does keep whatever
    ///                  UNIX permissions the file has intact though.
    ///                 
    ///
    pub fn open(&self, path: &Path, flags: OFlag, mode: Mode) -> Result<SmbcFile> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        trace!("Attempting to retrieve open function");
        let open_fn = try_ufnrc!(smbc_getFunctionOpen <- self.context);
        trace!("Sucessfully retrieved open function, attempting to apply function");

        let fd = result_from_ptr_mut(unsafe {
            open_fn(self.context.0, path.as_ptr(), flags.bits(), mode.bits())
        })?;
        if (fd as i64) < 0 {
            trace!(target: "smbc", "neg fd");
        }
        Ok(SmbcFile {
            smbc: Rc::clone(&self.context),
            fd: fd,
        })
    }

    ///
    /// Open a directory used to obtain directory entries.
    ///
    /// @param path      The smb url of the directory to open
    ///
    /// @return          Valid directory handle. < 0 on error with errno set:
    ///                  - EACCES Permission denied.
    ///                  - EINVAL A NULL file/URL was passed, or the URL would
    ///                  not parse, or was of incorrect form or smbc_init not
    ///                  called.
    ///                  - ENOENT durl does not exist, or name is an
    ///                  - ENOMEM Insufficient memory to complete the
    ///                  operation.
    ///                  - ENOTDIR name is not a directory.
    ///                  - EPERM the workgroup could not be found.
    ///                  - ENODEV the workgroup or server could not be found.
    ///
    pub fn opendir(&self, path: &Path) -> Result<SmbcDirectory> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        trace!("Attempting to retrieve opendir function");
        let opendir_fn = try_ufnrc!(smbc_getFunctionOpendir <- self.context);
        let handle = result_from_ptr_mut(unsafe { opendir_fn(self.context.0, path.as_ptr()) })?;
        if (handle as i64) < 0 {
            trace!("Error: neg directory fd");
        }
        Ok(SmbcDirectory {
            smbc: Rc::clone(&self.context),
            handle: handle,
        })
    }

    ///
    /// Please NOTE that MODE does not matter, since the
    /// function never actually uses the input mode...
    /// See https://ftp.samba.org/pub/pub/unpacked/SOC/2005/SAMBA_3_0/source/libsmb/libsmbclient.cg
    /// for details
    ///
    pub fn mkdir(&self, path: &Path, mode: Mode) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        trace!("Attempting to retrieve mkdir function");
        let mkdir_fn = try_ufnrc!(smbc_getFunctionMkdir <- self.context);
        let handle =
            to_result_with_le(unsafe { mkdir_fn(self.context.0, path.as_ptr(), mode.bits()) })?;
        if (handle as i64) < 0 {
            trace!("Error: neg directory fd");
        }
        Ok(())
    }

    ///
    /// Rename or move a file or directory.
    ///
    /// @param oldpath   The original smb url (source url) of file or
    ///                  directory to be moved
    ///
    /// @param newpath   The new smb url (destination url) of the file
    ///                  or directory after the move.  Currently nurl must
    ///                  be on the same share as ourl.
    ///
    /// @return          Nothing on success, Error with errno set:
    ///                  - EISDIR nurl is an existing directory, but ourl is
    ///                  not a directory.
    ///                  - EEXIST nurl is  a  non-empty directory,
    ///                  i.e., contains entries other than "." and ".."
    ///                  - EINVAL The  new  url  contained  a path prefix
    ///                  of the old, or, more generally, an  attempt was
    ///                  made  to make a directory a subdirectory of itself
    /// 		         or smbc_init not called.
    ///                  - ENOTDIR A component used as a directory in ourl
    ///                  or nurl path is not, in fact, a directory.  Or,
    ///                  ourl  is a directory, and newpath exists but is not
    ///                  a directory.
    ///                  - EACCES or EPERM Write access to the directory
    ///                  containing ourl or nurl is not allowed for the
    ///                  process's effective uid,  or  one of the
    ///                  directories in ourl or nurl did not allow search
    ///                  (execute) permission,  or ourl  was  a  directory
    ///                  and did not allow write permission.
    ///                  - ENOENT A  directory component in ourl or nurl
    ///                  does not exist.
    ///                  - EXDEV Rename across shares not supported.
    ///                  - ENOMEM Insufficient kernel memory was available.
    ///                  - EEXIST The target file, nurl, already exists.
    ///
    pub fn rename(&self, oldpath: &Path, newpath: &Path) -> Result<()> {
        let oldpath = CString::new(oldpath.as_os_str().as_bytes())?;
        let newpath = CString::new(newpath.as_os_str().as_bytes())?;
        let rename_fn = try_ufnrc!(smbc_getFunctionRename <- self.context);
        to_result_with_le(unsafe {
            rename_fn(
                self.context.0,
                oldpath.as_ptr(),
                self.context.0,
                newpath.as_ptr(),
            )
        })?;
        Ok(())
    }

    ///
    /// stat
    /// stat returns the meta attributes of a file/directory
    /// NOTE:
    /// block size is always 512
    /// nlink with be either 2 if the file is a directory or 1 otherwise
    /// blocks is (size+511)/512
    ///
    /// mode values depend on what attributes are active in smb.conf
    /// file modes will always by default have a minimum mode of
    /// 100444, directory 40555.
    ///
    /// if map archive = yes, you can add the XUSR flag to mode, (USR can be 4, 5)
    /// if map readonly = yes, you can add the WUSR flag to mode, (USR can be 4, 5(dir only), 6)
    /// (if both, USR permissions can be 4, 5, 6, or 7)
    /// if map system = yes, you can add the XGRP flag to mode, (GRP can be 4, 5)
    /// if map hidden = yes, you can add the XOTH flag to mode, (OTH can be 4, 5)
    ///
    /// m_time, c_time, a_time return the number of seconds since epoch
    ///
    /// See https://ftp.samba.org/pub/pub/unpacked/SOC/2005/SAMBA_3_0/source/libsmb/libsmbclient.c
    /// for details (you'll be surprised at how much of this is hard coded...)
    ///
    pub fn stat(&self, path: &Path) -> Result<stat> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let mut stat_buf: stat = unsafe { zeroed::<stat>() };
        let stat_fn = try_ufnrc!(smbc_getFunctionStat <- self.context);
        let res =
            to_result_with_le(unsafe { stat_fn(self.context.0, path.as_ptr(), &mut stat_buf) })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "stat failed");
        }
        Ok(stat_buf)
    }

    /**
     * NOTE!
     * DOES NOT WORK
     */
    /*pub fn statvfs(&self, path: &Path) -> Result<statvfs> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let mut stat_buf: statvfs = unsafe { zeroed::<statvfs>() };
        let statvfs_fn = try_ufnrc!(smbc_getFunctionStatVFS <- self.context);
        let res = to_result_with_le(unsafe {
            statvfs_fn(self.context.0, path.into_raw(), &mut stat_buf)
        })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "statvfs failed");
        }
        Ok(stat_buf)
    }*/

    ///@ingroup directory
    /// Unlink (delete) a file or directory.
    ///
    /// @param path      The smb url of the file to delete
    ///
    /// @return          Nothing on success, Error with errno set:
    ///                  - EACCES or EPERM Write  access  to the directory
    ///                  containing pathname is not allowed or one
    ///                  of  the  directories in pathname did not allow
    ///                  search (execute) permission
    ///                  - ENOENT A directory component in pathname does
    ///                  not exist
    ///                  - EINVAL NULL was passed in the file param or
    /// 		           smbc_init not called.
    ///                  - EACCES You do not have access to the file
    ///                  - ENOMEM Insufficient kernel memory was available
    ///
    pub fn unlink(&self, path: &Path) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let unlink_fn = try_ufnrc!(smbc_getFunctionUnlink <- self.context);
        unsafe {
            to_result_with_le(unlink_fn(self.context.0, path.as_ptr()))?;
        }
        Ok(())
    }

    ///
    /// Change the last modification time on a file
    ///
    /// @param path      The smb url of the file or directory to change
    ///                  the modification time of
    ///
    /// @param tbuf      An array of two timeval structures which contains,
    ///                  respectively, the desired access and modification times.
    ///                  NOTE: Only the tv_sec field off each timeval structure is
    ///                  used.  The tv_usec (microseconds) portion is ignored.
    ///
    /// @return          Nothing on success, Error with errno set:
    ///                  - EINVAL The client library is not properly initialized
    ///                  - EPERM  Permission was denied.
    ///
    pub fn utimes(&self, path: &Path, tbuf: *mut timeval) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let utimes_fn = try_ufnrc!(smbc_getFunctionUtimes <- self.context);
        unsafe {
            try!(to_result_with_le(utimes_fn(
                self.context.0,
                path.as_ptr(),
                tbuf
            )));
        }
        Ok(())
    }

    ///Get extended attributes for a file.
    ///
    /// @param url       The smb url of the file or directory to get extended
    ///                  attributes for.
    ///
    /// @param name      The name of an attribute to be retrieved.  Names are of
    ///                  one of the following forms:
    ///
    ///                     system.nt_sec_desc.<attribute name>
    ///                     system.nt_sec_desc.*
    ///                     system.nt_sec_desc.*+
    ///
    ///                  where <attribute name> is one of:
    ///
    ///                     revision
    ///                     owner
    ///                     owner+
    ///                     group
    ///                     group+
    ///                     acl:<sid>
    ///                     acl+:<sid>
    ///
    ///                  In the forms "system.nt_sec_desc.*" and
    ///                 "system.nt_sec_desc.*+", the asterisk and plus signs are
    ///                 literal, i.e. the string is provided exactly as shown, an
    ///                 the value parameter will return a complete security
    ///                  commas, or newlines (not spaces!).
    ///
    ///                 The plus sign ('+') indicates that SIDs should be mapped
    ///                  to names.  Without the plus sign, SIDs are not mapped;
    ///                 rather they are simply converted to a string format.
    ///                 
    ///                 or:
    ///                     system.dos_attr.<attribute name>
    ///                     system.dos_attr.*
    ///
    ///                  where <attribute name> is one of:
    ///
    ///                     mode
    ///                     c_time
    ///                     a_time
    ///                     m_time
    ///                     inode
    ///                     size
    ///                 or
    ///                     system.*
    ///                     system.*+
    ///
    ///                 The * attribute will get all values of a set (so system.* will
    ///                 return all DOS and ACL attributes, system.dos_attr.* all DOS
    ///                 attributes, etc.).  The commands with * may also exclude elements
    ///                 with ! delimiters (ex: system.*!nt_sec_desc.acl!dos_attr.mode will
    ///                 return all attributes excluding acl and mode)
    ///
    ///                 Use the SmbcXattr enum to build your input.
    ///
    /// @return          0 on success, < 0 on error with errno set:
    ///                  - EINVAL  The client library is not properly initialized
    ///                            or one of the parameters is not of a correct
    ///                           form
    ///                  - ENOMEM No memory was available for internal needs
    ///                  - EEXIST  If the attribute already exists and the flag
    ///                            SMBC_XATTR_FLAG_CREAT was specified
    ///                  - ENOATTR If the attribute does not exist and the flag
    ///                            SMBC_XATTR_FLAG_REPLACE was specified
    ///                  - EPERM   Permission was denied.
    ///                  - ENOTSUP The referenced file system does not support
    ///                            extended attributes
    ///
    pub fn getxattr(&self, path: &Path, attr: &SmbcXAttr) -> Result<Vec<u8>> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let name = CString::new(format!("{}", attr).as_bytes())?;
        let getxattr_fn = try_ufnrc!(smbc_getFunctionGetxattr <- self.context);
        // Set your buffer to capacity len here
        let len = to_result_with_le(unsafe {
            getxattr_fn(
                self.context.0,
                path.as_ptr(),
                name.as_ptr(),
                vec![].as_ptr() as *const _,
                0,
            )
        })? + 1;
        trace!("Sizing buffer to {}", len);
        let mut value: Vec<u8> = Vec::with_capacity(len as usize);
        if (len as i64) < 0 {
            trace!(target: "smbc", "getxattr failed");
        }
        let res = to_result_with_le(unsafe {
            getxattr_fn(
                self.context.0,
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr() as *const _,
                len as _,
            )
        })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "getxattr failed");
        }
        unsafe {
            value.set_len(len as usize);
        }

        Ok(value)
    }

    ///
    /// While this function is supposed to list only the applicable attributes
    /// of a file/directory, this funciton always returns all attribute names
    /// supported by NT file systems, regardless of whether the referenced
    /// file system supports extended attributes
    ///
    pub fn listxattr(&self, path: &Path) -> Result<Vec<u8>> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let listxattr_fn = try_ufnrc!(smbc_getFunctionListxattr <- self.context);
        // Set your buffer to capacity len here
        let temp: Vec<u8> = vec![];
        let len = to_result_with_le(unsafe {
            listxattr_fn(
                self.context.0,
                path.as_ptr(),
                temp.as_ptr() as *mut c_char,
                0,
            )
        })?;
        trace!("Sizing buffer to {}", len);
        let mut value: Vec<u8> = Vec::with_capacity(len as usize);
        if (len as i64) < 0 {
            trace!(target: "smbc", "listxattr failed");
        }

        let res = to_result_with_le(unsafe {
            listxattr_fn(
                self.context.0,
                path.as_ptr(),
                value.as_ptr() as *mut c_char,
                len as _,
            )
        })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "listxattr failed");
        }
        unsafe {
            value.set_len(len as usize);
        }
        Ok(value)
    }

    ///
    /// NOTE: removexattr only works for the following inputs:
    /// system.nt_sec_sesc.*
    /// system.nt_sec_sesc.*+
    /// system.nt_sec_desc.acl
    /// system.nt_sec_desc.acl+
    ///
    /// In order for removexattr to run, you must have in your config file:
    /// store dos attributes = yes and vfs objects = yes
    /// or vfs objects = yes
    ///
    /// Oh, and the reason why revision, owner(+), group(+) don't work is because of how sec_desc_parse works.  
    /// See https://ftp.samba.org/pub/pub/unpacked/SOC/2005/SAMBA_3_0/source/libsmb/libsmbclient.c
    /// for details
    ///
    pub fn removexattr(&self, path: &Path, attr: &SmbcXAttr) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let name = CString::new(format!("{}", attr).as_bytes())?;
        //let name = CString::new(name.to_string().as_bytes())?;
        let removexattr_fn = try_ufnrc!(smbc_getFunctionRemovexattr <- self.context);
        unsafe {
            to_result_with_le(removexattr_fn(self.context.0, path.as_ptr(), name.as_ptr()))?;
        }
        Ok(())
    }

    ///
    /// Please note that if your file has removed all acl attributes, setxattr
    /// commands may not work.  
    ///
    /// In your config file, if you do not have map archive = yes, map hidden = yes,
    /// map readonly = yes, map system = yes, some of your commands may not work,
    /// such as changing mode.  You may want to have both store dos attributes = yes
    /// and vfs objects = yes if you want both remove and setxattr to work.  
    ///
    /// As such, please note that your file ACL permissions do in fact effect
    /// whether or not you can make changes to a file as well.
    ///
    /// NOTE: setxattr on system.nt_sec_desc.group(+) does not work
    /// See https://ftp.samba.org/pub/pub/unpacked/SOC/2005/SAMBA_3_0/source/libsmb/libsmbclient.c
    /// for details (It uses the wrong value and therefore tries to change the owner instead
    /// of the group...)
    ///
    /// In general, You will probably have an easier time just setting all of the
    /// ACL attributes at once (removing extra), than individually considereing
    /// individually, changing group does not work
    ///
    pub fn setxattr(
        &self,
        path: &Path,
        attr: &SmbcXAttr,
        value: &SmbcXAttrValue,
        flags: XAttrFlags,
    ) -> Result<()> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        let len = format!("{}", value).len();
        let name = CString::new(format!("{}", attr).as_bytes())?;
        trace!("{:?}", name);
        let value = CString::new(format!("{}", value).as_bytes())?;
        trace!("{:?}, len {}", value, len);
        //let name = CString::new(name.to_string().as_bytes())?;
        let setxattr_fn = try_ufnrc!(smbc_getFunctionSetxattr <- self.context);
        let res = unsafe {
            setxattr_fn(
                self.context.0,
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr() as *const _,
                len as _,
                flags.bits() as _,
            )
        };
        if (res as i64) < 0 {
            trace!(target: "smbc", "setxattr failed");
            to_result_with_le(res)?;
        }
        Ok(())
    }
}

impl SmbcFile {
    ///
    /// Read from a file using an opened file handle.
    /// @param count   Size of buf in bytes
    ///
    /// @return          Vec of read bytes;
    ///                  ERROR:
    ///                  - EISDIR fd refers to a directory
    ///                  - EBADF  fd  is  not  a valid file descriptor or
    ///                    is not open for reading.
    ///                  - EINVAL fd is attached to an object which is
    ///                    unsuitable for reading, or no buffer passed or
    ///     		       smbc_init not called.
    ///
    /// PLEASE NOTE: read starts from the current file offset
    /// (So if you read 10 bytes, then read again, the second read starts
    /// from the 10th byte) So if you happen to have already read all the bytes,
    /// and have not lseeked back to the beginning,
    /// calling read again will give you an empty vec
    ///
    pub fn fread(&self, count: u64) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(count as usize);
        let read_fn = try_ufnrc!(smbc_getFunctionRead <- self.smbc);
        let bytes_read = to_result_with_le(unsafe {
            read_fn(
                self.smbc.0,
                self.fd,
                buf.as_mut_ptr() as *mut _,
                count as usize,
            )
        })?;
        if (bytes_read as i64) < 0 {
            trace!(target: "smbc", "read failed");
        }
        unsafe {
            buf.set_len(bytes_read as usize);
        }
        Ok(buf)
    }

    ///
    /// Write to a file using an opened file handle.
    /// @param buf       Pointer to buffer to recieve read data
    /// @return          Number of bytes written, < 0 on error with errno set:
    ///                  - EISDIR fd refers to a directory.
    ///                  - EBADF  fd  is  not  a valid file descriptor or
    ///                  is not open for reading.
    ///                  - EINVAL fd is attached to an object which is
    ///                  unsuitable for reading, or no buffer passed or
    ///     		     smbc_init not called.
    ///
    /// Please NOTE that fwrite writes from the current file offset
    ///
    pub fn fwrite(&self, buf: &[u8]) -> Result<isize> {
        let write_fn = try_ufnrc!(smbc_getFunctionWrite <- self.smbc);
        let bytes_wrote = to_result_with_le(unsafe {
            write_fn(
                self.smbc.0,
                self.fd,
                buf.as_ptr() as *const _,
                buf.len() as _,
            )
        })?;
        if (bytes_wrote as i64) < 0 {
            trace!(target: "smbc", "write failed");
        }
        Ok(bytes_wrote)
    }

    ///
    /// Seek to a specific location in a file.
    /// @param offset    Offset in bytes from whence
    ///
    /// @param whence    A location in the file:
    ///                  - SEEK_SET The offset is set to offset bytes from
    ///                  the beginning of the file
    ///                  - SEEK_CUR The offset is set to current location
    ///                  plus offset bytes.
    ///                  - SEEK_END The offset is set to the size of the
    ///                  file plus offset bytes.
    ///
    /// @return          Upon successful completion, lseek returns the
    ///                  resulting offset location as measured in bytes
    ///                  from the beginning  of the file. Otherwise, a value
    ///                  of (off_t)-1 is returned and errno is set to
    ///                  indicate the error:
    ///                  - EBADF  Fildes is not an open file descriptor.
    ///                  - EINVAL Whence is not a proper value or smbc_init
    ///     		     not called.
    ///
    pub fn lseek(&self, offset: i64, whence: i32) -> Result<off_t> {
        let lseek_fn = try_ufnrc!(smbc_getFunctionLseek <- self.smbc);
        let res = to_result_with_errno(
            unsafe { lseek_fn(self.smbc.0, self.fd, offset, whence) },
            EINVAL,
        )?;
        Ok(res as off_t)
    }

    /**
     * fstat
     * NOTE: stat notes apply
     * Please note that fstat called on a directory entry will not work
     * See fstatdir's comments below.
     * Please use stat for directory meta attributes
     */
    pub fn fstat(&self) -> Result<stat> {
        let mut stat_buf: stat = unsafe { zeroed::<stat>() };
        let fstat_fn = try_ufnrc!(smbc_getFunctionFstat <- self.smbc);
        let res = to_result_with_le(unsafe { fstat_fn(self.smbc.0, self.fd, &mut stat_buf) })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "fstat failed");
        }
        Ok(stat_buf)
    }

    /**
     * Does not Work
     */
    /*pub fn fstatvfs(&self) -> Result<statvfs> {
        let mut stat_buf: statvfs = unsafe { zeroed::<statvfs>() };
        let fstatvfs_fn = try_ufnrc!(smbc_getFunctionFstatVFS <- self.smbc);
        trace!("Applying fstatvfs");
        let res = to_result_with_le(unsafe { fstatvfs_fn(self.smbc.0, self.fd, &mut stat_buf) })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "statvfs failed");
        }
        Ok(stat_buf)
    }*/

    ///
    /// ftruncate
    /// Truncate a file given a file descriptor
    /// @param size      size to truncate the file to
    ///
    /// @return          Nothing on success;
    ///                  Error:
    ///                  - EBADF  filedes is bad.
    ///                  - EACCES Permission denied.
    ///                  - EBADF fd is not a valid file descriptor
    ///                  - EINVAL Problems occurred in the underlying routines
    /// 		           or smbc_init not called.
    ///                  - ENOMEM Out of memory
    ///
    pub fn ftruncate(&self, size: i64) -> Result<()> {
        let ftruncate_fn = try_ufnrc!(smbc_getFunctionFtruncate <- self.smbc);
        to_result_with_le(unsafe { ftruncate_fn(self.smbc.0, self.fd, size as off_t) })?;
        Ok(())
    }
}

///
/// Read trait for SmbcFile
/// pretty much does the same thing as fread above
///
impl Read for SmbcFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        trace!(target: "smbc", "reading file to buf [{:?};{}]", buf.as_ptr(), buf.len());
        let read_fn = try_ufnrc!(smbc_getFunctionRead <- self.smbc);
        let bytes_read = to_result_with_le(unsafe {
            read_fn(
                self.smbc.0,
                self.fd,
                buf.as_mut_ptr() as *mut _,
                buf.len() as _,
            )
        })?;
        Ok(bytes_read as usize)
    }
}

///
/// Write trait for smbcFile
/// Does the same thing as fwrite above
///
impl Write for SmbcFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        trace!(target: "smbc", "writing buf [{:?};{}] to file", buf.as_ptr(), buf.len());
        let write_fn = try_ufnrc!(smbc_getFunctionWrite <- self.smbc);
        let bytes_wrote = to_result_with_le(unsafe {
            write_fn(
                self.smbc.0,
                self.fd,
                buf.as_ptr() as *const _,
                buf.len() as _,
            )
        })?;
        Ok(bytes_wrote as usize)
    }

    /// Do nothing for SmbFile
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

///
/// Seek trait for SmbcFile if needed
/// You can just call lseek though...
///
impl Seek for SmbcFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        trace!(target: "smbc", "seeking file {:?}", pos);
        let lseek_fn = try_ufnrc!(smbc_getFunctionLseek <- self.smbc);
        let (whence, off) = match pos {
            SeekFrom::Start(p) => (SEEK_SET, p as off_t),
            SeekFrom::End(p) => (SEEK_END, p as off_t),
            SeekFrom::Current(p) => (SEEK_CUR, p as off_t),
        };
        let res = to_result_with_errno(
            unsafe { lseek_fn(self.smbc.0, self.fd, off, whence as i32) },
            EINVAL,
        )?;
        Ok(res as u64)
    }
}

impl SmbcDirectory {
    /**
     * PLEASE NOTE!!!!!
     * fstatdir is NOT implemented in the SMB Client library:
     * See https://ftp.samba.org/pub/pub/unpacked/SOC/2005/SAMBA_3_0/source/libsmb/libsmbclient.c * for details.
     *
     * Therefore this function is useless
     */
    /*
    pub fn fstatdir(&self) -> Result<stat> {
        let mut stat_buf: stat = unsafe { zeroed::<stat>() };
        let fstatdir_fn = try_ufnrc!(smbc_getFunctionFstatdir <- self.smbc);
        let res =
            to_result_with_le(unsafe { fstatdir_fn(self.smbc.0, self.handle, &mut stat_buf) })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "statdir failed");
        }
        Ok(stat_buf)
    }*/

    /**
     * Iterator implemented, not necessary
     */
    /*pub fn getdents(&mut self, count : i64) -> io::Result<Vec<SmbcDirEntry>>
    {
        let mut dirp: Vec<smbc_dirent> = Vec::with_capacity(count as usize);
        for i in 0..count as usize
        {
            dirp.push(unsafe{zeroed::<smbc_dirent>()});
        }
        trace!("attempting to retrieve getdents function");
        let getdents_fn = try_ufnrc!(smbc_getFunctionGetdents <- self.smbc);
        trace!("Applying getdents function");
        let res = try!(to_result_with_le(
            getdents_fn(self.smbc.0,
                     self.handle,
                     dirp.as_mut_ptr() as *mut smbc_dirent,
                     count as c_int)
        ));
        if (res as i64) < 0 {
            trace!(target: "smbc", "getdents failed");
        }
        let mut dirs : Vec<SmbcDirEntry> = Vec::new();
        for dirent in dirp {
            let filename = unsafe{CStr::from_ptr((dirent.name)[0] as *const i8)};
        let d_type = match SmbcType::from(dirent.smbc_type) {
            Ok(ty) => ty,
            Err(e) => {
                return Err(e);
            }
        };
        let comment = unsafe{CStr::from_ptr((dirent).comment).to_string_lossy().into_owned()};
        dirs.push(SmbcDirEntry{
            s_type : d_type,
            //size : (dirent).dirlen,
            comment : comment,
            path: PathBuf::from(filename.to_string_lossy().into_owned()),
        })
        }
        Ok(dirs)
    }*/
    /***
     * Output hardcoded, do not use
     */
    /*pub fn statvfsdir(&self) -> Result<statvfs> {
        let mut stat_buf: statvfs = unsafe { zeroed::<statvfs>() };
        let fstatvfs_fn = try_ufnrc!(smbc_getFunctionFstatVFS <- self.smbc);
        trace!("Applying fstatvfs");
        let res = to_result_with_le(unsafe { fstatvfs_fn(self.smbc.0, self.handle, &mut stat_buf) })?;
        if (res as i64) < 0 {
            trace!(target: "smbc", "statvfs failed");
        }
        Ok(stat_buf)
    }*/

    ///
    /// readdir
    /// Get a single directory entry.
    /// @return          SmbcDirEntry of next directory else
    ///                  error occurs or end-of-directory is reached:
    ///                  - EBADF Invalid directory handle
    ///                  - EINVAL smbc_init() failed or has not been called
    ///
    pub fn readdir(&mut self) -> io::Result<SmbcDirEntry> {
        let readdir_fn = try_ufnrc!(smbc_getFunctionReaddir <- self.smbc);
        trace!("Attempting to apply readdir function {:?}", self.handle);
        let dirent = result_from_ptr_mut(unsafe { readdir_fn(self.smbc.0, self.handle) })?;
        trace!("readdir function successful!");
        if dirent.is_null() {
            let e = Error::new(ErrorKind::Other, "dirent null");
            return Err(e);
        }
        let mut buff: Vec<i8> = Vec::new();
        let len = unsafe { (*dirent).namelen };
        let ptr = unsafe { (&(*dirent).name) as *const i8 };
        for x in 0..len {
            trace!("namelen : {}", len);
            trace!("{:?}", unsafe { *ptr.offset(x as isize) });
            buff.push(unsafe { *ptr.offset(x as isize) });
        }
        let name_buff: Vec<u8> = buff.iter().map(|c| c.clone() as u8).collect();
        trace!("Cursor name {:?}", name_buff);
        let filename = String::from_utf8_lossy(&name_buff);
        trace!("Filename: {:?}", filename);
        let d_type = match SmbcType::from(unsafe { (*dirent).smbc_type }) {
            Ok(ty) => ty,
            Err(e) => {
                return Err(e);
            }
        };
        let comment = unsafe {
            CStr::from_ptr((*dirent).comment)
                .to_string_lossy()
                .into_owned()
        };
        Ok(SmbcDirEntry {
            s_type: d_type,
            comment: comment,
            path: PathBuf::from(filename.into_owned()),
        })
    }

    ///
    /// lseek on directories.
    ///
    /// smbc_lseekdir() may be used in conjunction with smbc_readdir() and
    /// smbc_telldir(). (rewind by smbc_lseekdir(fd, NULL))
    ///
    /// @param offset    The offset (as returned by smbc_telldir). Can be
    ///                  NULL, in which case we will rewind
    ///
    /// @return          Nothing on success;
    ///                  Error:
    ///                  - EBADF dh is not a valid directory handle
    ///                  - ENOTDIR if dh is not a directory
    ///                  - EINVAL offset did not refer to a valid dirent or
    ///             	   smbc_init not called.
    ///
    pub fn lseekdir(&self, offset: i64) -> Result<()> {
        let lseekdir_fn = try_ufnrc!(smbc_getFunctionLseekdir <- self.smbc);
        let res = to_result_with_errno(
            unsafe { lseekdir_fn(self.smbc.0, self.handle, offset as off_t) },
            EINVAL,
        )?;
        Ok(())
    }

    ///
    /// Get the current directory offset.
    /// smbc_telldir() may be used in conjunction with smbc_readdir() and
    /// smbc_lseekdir().
    /// @return         The current location in the directory stream or -1
    ///                 if an error occur.  The current location is not
    ///                 an offset. Becuase of the implementation, it is a
    ///                 handle that allows the library to find the entry
    ///                 later.
    ///                 - EBADF dh is not a valid directory handle
    ///                 - EINVAL smbc_init() failed or has not been called
    ///                 - ENOTDIR if dh is not a directory
    ///
    pub fn telldir(&mut self) -> Result<off_t> {
        let telldir_fn = try_ufnrc!(smbc_getFunctionTelldir <- self.smbc);
        let res = to_result_with_errno(unsafe { telldir_fn(self.smbc.0, self.handle) }, EINVAL)?;
        Ok(res as off_t)
    }
}

///
/// An iterator over an SmbcDirectory
/// When you use opendir to open a directory, you can use this iterator
/// to loop through all files/subdirectories
/// (Or you can just call readdir over an over)
///
impl Iterator for SmbcDirectory {
    type Item = io::Result<SmbcDirEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        trace!("Attempting to retrieve readdir function");
        trace!("Handle: {:?}", self.handle);
        let readdir_fn = try_iter!(smbc_getFunctionReaddir <- self.smbc);
        trace!("Readdir retrieved, attempting to apply function");
        let dirent =
            match result_from_ptr_mut(unsafe { readdir_fn.unwrap()(self.smbc.0, self.handle) }) {
                Ok(d) => d,
                Err(e) => {
                    trace!("Error! {:?}", e);
                    return None;
                }
            };
        trace!("Readdir successful!");
        if dirent.is_null() {
            trace!("Directory is NULL!!! T");
            // Null means we're done
            return None;
        }
        let mut buff: Vec<i8> = Vec::new();
        let len = unsafe { (*dirent).namelen };
        let ptr = unsafe { (&(*dirent).name) as *const i8 };
        for x in 0..len {
            trace!("namelen : {}", len);
            trace!("{:?}", unsafe { *ptr.offset(x as isize) });
            buff.push(unsafe { *ptr.offset(x as isize) });
        }
        let name_buff: Vec<u8> = buff.iter().map(|c| c.clone() as u8).collect();
        trace!("Cursor name {:?}", name_buff);

        let filename = String::from_utf8_lossy(&name_buff);
        trace!("Filename: {:?}", filename);
        let s_type = match unsafe { SmbcType::from((*dirent).smbc_type) } {
            Ok(ty) => ty,
            Err(e) => {
                return Some(Err(e));
            }
        };
        trace!("FileType: {:?}", s_type);
        let comment = unsafe {
            CStr::from_ptr((*dirent).comment)
                .to_string_lossy()
                .into_owned()
        };
        trace!("Comment: {:?}", comment);
        Some(Ok(SmbcDirEntry {
            s_type,
            comment: comment,
            path: PathBuf::from(filename.into_owned()),
        }))
    }
}

///
/// Seek trait for SmbcDirectory
/// Granted, you COULD just use lseek and telldir, but
/// in case you need to have the trait...
///
impl Seek for SmbcDirectory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        trace!(target: "smbc", "seeking file {:?}", pos);
        let lseekdir_fn = try_ufnrc!(smbc_getFunctionLseekdir <- self.smbc);
        let (_, off) = match pos {
            SeekFrom::Start(p) => (SEEK_SET, p as off_t),
            SeekFrom::End(p) => (SEEK_END, p as off_t),
            SeekFrom::Current(p) => (SEEK_CUR, p as off_t),
        };
        let res = to_result_with_errno(
            unsafe { lseekdir_fn(self.smbc.0, self.handle, off as off_t) },
            EINVAL,
        )?;
        Ok(res as u64)
    }
}

pub fn num_hours(timestamp: timeval) -> i64 {
    num_seconds(timestamp) / 3600
}

pub fn num_minutes(timestamp: timeval) -> i64 {
    num_seconds(timestamp) / 60
}

pub fn num_seconds(timestamp: timeval) -> i64 {
    if timestamp.tv_sec < 0 && timestamp.tv_usec > 0 {
        (timestamp.tv_sec + 1) as i64
    } else {
        timestamp.tv_sec as i64
    }
}

pub fn num_milliseconds(timestamp: timeval) -> i64 {
    num_microseconds(timestamp) / 1000
}

pub fn num_microseconds(timestamp: timeval) -> i64 {
    let secs = num_seconds(timestamp) * 1000000;
    let usecs = micros_mod_sec(timestamp);
    secs + usecs as i64
}

fn micros_mod_sec(timestamp: timeval) -> __suseconds_t {
    if timestamp.tv_sec < 0 && timestamp.tv_usec > 0 {
        //MICROS PER SECOND = 1,000,000
        timestamp.tv_usec - 1000000 as __suseconds_t
    } else {
        timestamp.tv_usec
    }
}

pub fn stat_hours(timestamp: timespec) -> i64 {
    stat_seconds(timestamp) / 3600
}

pub fn stat_minutes(timestamp: timespec) -> i64 {
    stat_seconds(timestamp) / 60
}

pub fn stat_seconds(timestamp: timespec) -> i64 {
    if timestamp.tv_sec < 0 && timestamp.tv_nsec > 0 {
        (timestamp.tv_sec + 1) as i64
    } else {
        timestamp.tv_sec as i64
    }
}

pub fn stat_milliseconds(timestamp: timespec) -> i64 {
    stat_microseconds(timestamp) / 1000
}

pub fn stat_microseconds(timestamp: timespec) -> i64 {
    let secs = stat_seconds(timestamp) * 1000000;
    let usecs = stat_micros_mod_sec(timestamp);
    secs + usecs as i64
}

fn stat_micros_mod_sec(timestamp: timespec) -> __syscall_slong_t {
    if timestamp.tv_sec < 0 && timestamp.tv_nsec > 0 {
        //MICROS PER SECOND = 1,000,000
        timestamp.tv_nsec - 1000000 as __syscall_slong_t
    } else {
        timestamp.tv_nsec
    }
}

pub fn print_timeval_secs(timestamp: timeval) {
    let time = num_seconds(timestamp);
    let naive_datetime = NaiveDateTime::from_timestamp(time, 0);
    let datetime: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
    println!("{:?}", datetime);
}

pub fn print_timespec_secs(timestamp: timespec) {
    let time = stat_seconds(timestamp);
    let naive_datetime = NaiveDateTime::from_timestamp(time, 0);
    let datetime: DateTime<Utc> = DateTime::from_utc(naive_datetime, Utc);
    println!("{:?}", datetime);
}