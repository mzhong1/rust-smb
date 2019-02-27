use crate::smbc::*;
use nom::{types::CompleteByteSlice, *};
use std::str::*;

/*REVISION:1,
OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,
GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,
ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,
ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,
MODE:0x22,SIZE:0,A_TIME:14000000,
M_TIME:16000000,C_TIME:16000000,
INODE:415544


REVISION:1,
OWNER:TESTING\\superuser123,
GROUP:Unix Group\\superuser123,
ACL:\\Everyone:0/0/0x00120089,
ACL:Unix Group\\adm:0/3/0x001f01ff,
ACL:Unix Group\\superuser123:0/0/0x001f019f,
ACL:TESTING\\superuser123:0/0/0x001f019f,
MODE:0x80,SIZE:0,A_TIME:1543599732,
M_TIME:1543599732,C_TIME:1543599732,
INODE:393467\u{0}
 */

//let sid = "S-1-2-3-5656657-12363634513425-334";

#[test]
fn test_hex_num() {
    let test = "1f46c".to_string();
    let bytes = test.as_bytes();
    hex_num(CompleteByteSlice(&bytes)).unwrap();
}

#[test]
fn test_dec_num() {
    let test = "12345".to_string();
    let bytes = test.as_bytes();
    dec_num(nom::types::CompleteByteSlice(&bytes)).unwrap();
}

#[test]
fn test_list_dash() {
    let test = "1-2-3-45".to_string();
    let bytes = test.as_bytes();
    list_dash(CompleteByteSlice(&bytes)).unwrap();
}

#[test]
fn test_sid_parse() {
    let test = "S-1-22-2-1001".to_string();
    let sid = test.as_bytes();
    sid_parse(CompleteByteSlice(&sid)).unwrap();
}

#[test]
fn test_xattrmask_parse() {
    let testmode = "0x001f01ff".to_string();
    let modebytes = testmode.as_bytes();

    xattrmask_parse(CompleteByteSlice(&modebytes)).unwrap();
}

#[test]
fn test_aceflag_parse() {
    let testaflags = "11".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceflag_parse(CompleteByteSlice(&aflagbytes)).unwrap();
    let testaflags = "8".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceflag_parse(CompleteByteSlice(&aflagbytes)).unwrap();
    let testaflags = "7".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceflag_parse(CompleteByteSlice(&aflagbytes)).unwrap();
    let testaflags = "1".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceflag_parse(CompleteByteSlice(&aflagbytes)).unwrap();
    let testaflags = "0".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceflag_parse(CompleteByteSlice(&aflagbytes)).unwrap();
}

#[test]
fn test_bool_num() {
    let testaflags = "7".to_string();
    let aflagbytes = testaflags.as_bytes();
    println!("Test bool_num {:?}", bool_num(CompleteByteSlice(&aflagbytes)));
    let testaflags = "1".to_string();
    let aflagbytes = testaflags.as_bytes();
    bool_num(CompleteByteSlice(&aflagbytes)).unwrap();
    let testaflags = "0".to_string();
    let aflagbytes = testaflags.as_bytes();
    bool_num(CompleteByteSlice(&aflagbytes)).unwrap();
}

#[test]
fn test_aceatype_parse() {
    let testaflags = "7".to_string();
    let aflagbytes = testaflags.as_bytes();
    println!("Test aceatype_parse {:?}", aceatype_parse(CompleteByteSlice(&aflagbytes)));
    let testaflags = "0".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceatype_parse(CompleteByteSlice(&aflagbytes)).unwrap();
    let testaflags = "1".to_string();
    let aflagbytes = testaflags.as_bytes();
    aceatype_parse(CompleteByteSlice(&aflagbytes)).unwrap();
}

#[test]
fn test_ace_parse() {
    let test = "S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test ace parse {:?}", ace_parse(CompleteByteSlice(&bytes)));

    let test = "Unix Group\\adm:0/3/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test ace parse {:?}", ace_parse(CompleteByteSlice(&bytes)));
    let test = "\\Everyone:0/0/0x00120089".to_string();
    let bytes = test.as_bytes();
    println!("Test ace parse {:?}", ace_parse(CompleteByteSlice(&bytes)));
}
#[test]
fn test_acl_parse() {
    let test = "ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test acl parse {:?}", acl_parse(CompleteByteSlice(&bytes)));

    let test = "ACL:Unix Group\\adm:0/3/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test acl parse {:?}", acl_parse(CompleteByteSlice(&bytes)));
    let test = "ACL:\\Everyone:0/0/0x00120089".to_string();
    let bytes = test.as_bytes();
    println!("Test acl parse {:?}", acl_parse(CompleteByteSlice(&bytes)));
}

#[test]
fn test_dosmode_parse() {
    let test = "0x20".to_string();
    let bytes = test.as_bytes();
    let mode = dosmode_parse(CompleteByteSlice(&bytes)).unwrap().1;
    assert_eq!(mode, DosMode::ARCHIVE);
}

#[test]
fn test_mode_xattr_parse() {
    let test = "0x20".to_string();
    let bytes = test.as_bytes();
    let mode = mode_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test modexattr {:?}", mode);
}

#[test]
fn test_mode_all_parse() {
    let test = "MODE:0x20".to_string();
    let bytes = test.as_bytes();
    let mode = mode_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test modexattr {:?}", mode);
}

#[test]
fn test_groupplus_all_parse() {
    let test = "GROUP:Unix Group\\superuser123".to_string();
    let bytes = test.as_bytes();
    let mode = groupplus_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test groupplus all parse {:?}", mode);
    let test = "GROUP:TESTING\\superuser123,".to_string();
    let bytes = test.as_bytes();
    let mode = groupplus_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test groupplus all parse {:?}", mode);
}

#[test]
fn test_groupsid_all_parse() {
    let test = "GROUP:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = groupsid_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test groupsid all parse {:?}", mode);
}

#[test]
fn test_group_all_parse() {
    let test = "GROUP:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = group_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test group all parse {:?}", mode);
    let test = "GROUP:Unix Group\\superuser123,".to_string();
    let bytes = test.as_bytes();
    let mode = group_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test group all parse {:?}", mode);
}

#[test]
fn test_ownerplus_all_parse() {
    let test = "OWNER:TESTING\\superuser123".to_string();
    let bytes = test.as_bytes();
    let mode = ownerplus_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ownerplus all parse {:?}", mode);
    let test = "OWNER:TESTING\\superuser123,OWNER:Testing".to_string();
    let bytes = test.as_bytes();
    let mode = ownerplus_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ownerplus all parse {:?}", mode);
}

#[test]
fn test_ownersid_all_parse() {
    let test = "OWNER:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = ownersid_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ownersid all parse {:?}", mode);
}

#[test]
fn test_owner_all_parse() {
    let test = "OWNER:TESTING\\superuser123".to_string();
    let bytes = test.as_bytes();
    let mode = owner_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test owner all parse {:?}", mode);
    let test = "OWNER:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = owner_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test owner all parse {:?}", mode);
}

#[test]
fn test_revision_all_parse() {
    let test = "REVISION:1".to_string();
    let bytes = test.as_bytes();
    let rev = revision_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test revision all parse {:?}", rev)
}

#[test]
fn test_nt_sec_num_xattr_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_num_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec num xattr parse {:?}", val);
}

#[test]
fn test_nt_sec_name_xattr_parse() {
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_name_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec name xattr parse {:?}", val);
}

#[test]
fn test_nt_sec_xattr_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec xattr parse {:?}", val);
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec xattr parse {:?}", val);
}

#[test]
fn test_nt_sec_num_all_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_num_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec num all parse {:?}", val);
}

#[test]
fn test_nt_sec_name_all_parse() {
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_name_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec name all parse {:?}", val);
}

#[test]
fn test_nt_sec_all_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec all parse {:?}", val);
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test nt sec all parse {:?}", val);
}

#[test]
fn test_read_string() {
    let test = "asdousajhfb12323525184328,99999".to_string();
    let bytes = test.as_bytes();
    let val = read_string(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test read string {:?}", val);
    let test = "asdousa jhfb 12323525184328 99999".to_string();
    let bytes = test.as_bytes();
    let val = read_string(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test read string {:?}", val);
}

#[test]
fn test_ace_all_parse() {
    let test = "ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = ace_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ace all_parse {:?}", val);
    let test = "ACL:\\Everyone:0/0/0x001f01ff,ACL:Unix Group\\adm:0/0/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f01ff,ACL:TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = ace_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ace all_parse {:?}", val);
}

#[test]
fn test_acl_xattr_parse() {
    let test = "S-1-1-0:0/0/0x001f01ff,S-1-22-2-4:0/0/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = acl_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test acl xattr_parse {:?}", val);
    let test = "\\Everyone:0/0/0x001f01ff,Unix Group\\adm:0/0/0x001f01ff,Unix Group\\superuser123:0/0/0x001f01ff,TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = acl_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test acl xattr_parse {:?}", val);
}

#[test]
fn test_aclsid_parse() {
    let test = "S-1-1-0:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aclsid_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test aclsid_parse {:?}", val);
    let test = "Unix Group\\adm:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aclsid_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test aclsid_parse {:?}", val);
}

#[test]
fn test_aceall_xattr_parse() {
    let test = "S-1-1-0:0/0/0x001f01ff,S-1-22-2-4:0/0/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aceall_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test aceall xattr_parse {:?}", val);
    let test = "\\Everyone:0/0/0x001f01ff,Unix Group\\adm:0/0/0x001f01ff,Unix Group\\superuser123:0/0/0x001f01ff,TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aceall_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test aceall xattr_parse {:?}", val);
}

#[test]
fn test_sid_xattr_parse() {
    let test = "S-1-1-0".to_string();
    let bytes = test.as_bytes();
    let val = sid_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test sid_xattr_parse {:?}", val);
}

#[test]
fn test_unsigned_xattr_parse() {
    let test = "15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = unsigned_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test unsigned_xattr_parse {:?}", val);
    let test = "0".to_string();
    let bytes = test.as_bytes();
    let val = unsigned_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test unsigned_xattr_parse {:?}", val);
}

#[test]
fn test_atime_all_parse() {
    let test = "A_TIME:15123213".to_string();
    let bytes = test.as_bytes();
    let val = atime_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test atime_all_parse {:?}", val);
}

#[test]
fn test_mtime_all_parse() {
    let test = "M_TIME:15123213".to_string();
    let bytes = test.as_bytes();
    let val = mtime_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test mtime_all_parse {:?}", val);
}

#[test]
fn test_ctime_all_parse() {
    let test = "C_TIME:15123213".to_string();
    let bytes = test.as_bytes();
    let val = ctime_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ctime_all_parse {:?}", val);
}

#[test]
fn test_inode_all_parse() {
    let test = "INODE:15".to_string();
    let bytes = test.as_bytes();
    let val = inode_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test inode_all_parse {:?}", val);
}

#[test]
fn test_sdec_num() {
    let test = "12345".to_string();
    let bytes = test.as_bytes();
    sdec_num(nom::types::CompleteByteSlice(&bytes)).unwrap();
    let test = "-12345".to_string();
    let bytes = test.as_bytes();
    sdec_num(nom::types::CompleteByteSlice(&bytes)).unwrap();
}

#[test]
fn test_signed_xattr_parse() {
    let test = "-15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = signed_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test signed_xattr_parse {:?}", val);
    let test = "1230".to_string();
    let bytes = test.as_bytes();
    let val = signed_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test signed_xattr_parse {:?}", val);
}

#[test]
fn test_size_all_parse() {
    let test = "SIZE:15".to_string();
    let bytes = test.as_bytes();
    let val = size_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test size_all_parse {:?}", val);
    let test = "SIZE:-15".to_string();
    let bytes = test.as_bytes();
    let val = size_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test size_all_parse {:?}", val);
}

#[test]
fn test_dos_xattr_parse() {
    let test =
        "MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825"
            .to_string();
    let bytes = test.as_bytes();
    let val = dos_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test dos_xattr_parse {:?}", val);
}

#[test]
fn test_dos_all_parse() {
    let test =
        "MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825"
            .to_string();
    let bytes = test.as_bytes();
    let val = dos_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test dos_all_parse {:?}", val);
}

#[test]
fn test_system_all_parse() {
    let test = "REVISION:1,OWNER:S-1-22-2-4,GROUP:S-1-22-2-1001,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = system_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test system_all_parse {:?}", val);
    let test = "REVISION:1,OWNER:Unix Group\\adm,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x001f01ff,ACL:Unix Group\\adm:0/0/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f01ff,ACL:TESTING\\superuser123:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = system_all_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test system_all_parse {:?}", val);
}

#[test]
fn test_string_sid() {
    let test = "\\Everyone:".to_string();
    let bytes = test.as_bytes();
    let val = string_sid(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test stringsid {:?}", val);
}

#[test]
fn test_sidplus_xattr_parse() {
    let test = "\\Everyone".to_string();
    let bytes = test.as_bytes();
    let val = sidplus_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test sidplus xattr parse {:?}", val);
}

#[test]
fn test_ace_xattr_parse() {
    let test = "0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = ace_xattr_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ace xattr parse {:?}", val);
}

#[test]
fn test_acestat_parse() {
    let test = "0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = acestat_parse(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test ace stat parse {:?}", val);
}

#[test]
fn test_xattr_parser() {
    //System.*
    let test = "REVISION:1,OWNER:S-1-22-2-4,GROUP:S-1-22-2-1001,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser System.* {:?}", val);
    let test = "REVISION:1,OWNER:Unix Group\\adm,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x001f01ff,ACL:Unix Group\\adm:0/0/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f01ff,ACL:TESTING\\superuser123:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser System.* {:?}", val);
    //Dos_Attr.*
    let test =
        "MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825"
            .to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Dos_Attr.* {:?}", val);
    //Acl.*
    let test = "\\Everyone:0/0/0x001f01ff,Unix Group\\adm:0/0/0x001f01ff,Unix Group\\superuser123:0/0/0x001f01ff,TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Acl.* {:?}", val);
    let test = "S-1-1-0:0/0/0x001f01ff,S-1-22-2-4:0/0/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Acl.* {:?}", val);
    //Nt_Sec_Desc.*
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Nt_Sec_Desc.* {:?}", val);
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Nt_sec_Desc.* {:?}", val);
    //.acl:Sid
    let test = "0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Acl:SID {:?}", val);
    //.group | .owner
    let test = "S-1-1-0-123123213".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser SID {:?}", val);
    //.group+ | .owner+
    let test = "Unix Group\\superuser123".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser SIDSTRING {:?}", val);
    //revision | a_time | c_time | m_time | inode | (sometimes size)
    let test = "15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser USIGN {:?}", val);
    let test = "0".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser USIGN {:?}", val);
    //mode
    let test = "0x20".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser MODE {:?}", val);
    let test = "0x31".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser MODE {:?}", val);
    //size, granted, it would only work for negative size values...which would never happen...
    let test = "-15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser ISIGN {:?}", val);
    let test = "S-1-1-0:0/11/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser sid {:?}", val);

    let test = "S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,S-1-3-0:0/11/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-3-1:0/11/0x001f01ff,S-1-1-0:0/3/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(CompleteByteSlice(&bytes)).unwrap().1;
    println!("Test xattr_parser Dir ACLS {:?}", val);
}

/// Parse a decimal number
named!(dec_num(CompleteByteSlice<'_>) -> u64,
       do_parse!(n: take_while1!(is_digit)
                 >> ({
                     let s = String::from_utf8_lossy(n.as_bytes());
                     u64::from_str_radix(&s, 10).unwrap()
                 })));

/// Parse a signed decimal number
named!(sdec_num(CompleteByteSlice<'_>) -> i64,
       do_parse!(sign: opt!(tag!("-"))
                 >> n: take_while1!(is_digit)
                 >> ({
                     let s = String::from_utf8_lossy(n.as_bytes());
                     let i = i64::from_str_radix(&s, 10).unwrap();
                     match sign {
                         Some(_) => -i,
                         None => i,
                     }
                 })));

/// Parse a Hex number
named!(hex_num(CompleteByteSlice<'_>) -> i32,
       do_parse!(n: alt!(take_while1!(is_hex_digit) | take_while!(is_digit))
                 >> ({
                     let s = String::from_utf8_lossy(n.as_bytes());
                     i32::from_str_radix(&s, 16).unwrap()
                 })));

/// Parse an XAttrMask
named!(xattrmask_parse(CompleteByteSlice<'_>) -> XAttrMask,
       do_parse!(tag!("0x") >> num: hex_num >> (XAttrMask::from_bits(num).unwrap())));

/// Parse an AceFlag
named!(aceflag_parse(CompleteByteSlice<'_>) -> AceFlag,
       do_parse!(num: dec_num >> (AceFlag::from_bits(num as i32).unwrap())));

/// parse a binary number (0 or 1 only)
named!(bool_num(CompleteByteSlice<'_>) -> i32,
       do_parse!(i: alt!(recognize!(tag!("0")) | recognize!(tag!("1")))
                 >> ({
                     let s = String::from_utf8_lossy(i.as_bytes());
                     i32::from_str_radix(&s, 2).unwrap()
                 })));

/// Parse an AceAtype
named!(aceatype_parse(CompleteByteSlice<'_>) -> AceAtype,
       do_parse!(num: bool_num
                 >> (match num {
                     1 => AceAtype::DENIED,
                     0 => AceAtype::ALLOWED,
                     _ => AceAtype::ALLOWED,
                 })));

/// Parse a DosMode
named!(dosmode_parse(CompleteByteSlice<'_>) -> DosMode,
       do_parse!(tag!("0x") >> num: hex_num >> (DosMode::from_bits(num).unwrap())));

/// Individual mode get parse
named!(mode_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(dos: exact!(dosmode_parse) >> (SmbcXAttrValue::Mode(dos))));

/// Mode parse for .* call
named!(mode_all_parse(CompleteByteSlice<'_>) -> SmbcDosValue,
       do_parse!(tag_no_case!("MODE:") >> dos: dosmode_parse >> (SmbcDosValue::MODE(dos))));

/// collect numbers seperated by -
named!(list_dash(CompleteByteSlice<'_>) -> Vec<u64>,
       do_parse!(nums: separated_list!(tag!("-"), dec_num) >> (nums)));

/// Parse a numeric SID
named!(pub sid_parse(CompleteByteSlice<'_>) -> Sid,
    do_parse!(
        tag!("S-1-") >>
        nums: list_dash >>
        (
            Sid(nums)
        )
    )
);

/// Parse a named SID for named individual SID's from ACL+
named!(string_sid(CompleteByteSlice<'_>) -> String,
       do_parse!(sid: take_until!(":") >> (from_utf8(sid.as_bytes()).unwrap().to_string())));

/// Parse a named SID
named!(sidplus_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(sid: exact!(read_string) >> (SmbcXAttrValue::SidPlus(sid))));

/// Parse a named SID for Group+ (.* call)
named!(groupplus_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(tag!("GROUP:") >> sid: read_string >> (SmbcAclValue::GroupPlus(sid))));

/// Parse a numeric SID for Group (.* call)
named!(groupsid_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(tag!("GROUP:") >> sid: sid_parse >> (SmbcAclValue::Group(sid))));

/// parse a SID for Group(+) (.* call)
named!(group_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(grp: alt!(groupsid_all_parse | groupplus_all_parse) >> (grp)));

/// Parse an SID for Owner+ (.* call)
named!(ownerplus_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(tag!("OWNER:") >> sid: read_string >> (SmbcAclValue::OwnerPlus(sid))));

/// Parse an SID for Owner (.* call)
named!(ownersid_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(tag!("OWNER:") >> sid: sid_parse >> (SmbcAclValue::Owner(sid))));

/// Parse an SID for Owner(+) (.* call)
named!(owner_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(own: alt!(ownersid_all_parse | ownerplus_all_parse) >> (own)));

/// Parse a num for Revision (.* call)
named!(revision_all_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(tag!("REVISION:") >> n: dec_num >> (SmbcAclValue::Revision(n))));

/// Parse a numeric system.nt_sec_desc.* call to an XAttrValue
named!(nt_sec_num_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(rev: revision_all_parse
                 >> tag!(",")
                 >> own: owner_all_parse
                 >> tag!(",")
                 >> grp: group_all_parse
                 >> tag!(",")
                 >> acl: ace_all_parse
                 >> ({
                     let mut aval: Vec<SmbcAclValue> = vec![];
                     aval.push(rev);
                     aval.push(own);
                     aval.push(grp);
                     aval.extend(acl);
                     SmbcXAttrValue::AclAll(aval)
                 })));

/// Parse a named system.nt_sec_desc.*+ call to an XAttrValue
named!(nt_sec_name_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(rev: revision_all_parse
                 >> tag!(",")
                 >> own: owner_all_parse
                 >> grp: group_all_parse
                 >> acl: ace_all_parse
                 >> ({
                     let mut aval: Vec<SmbcAclValue> = vec![];
                     aval.push(rev);
                     aval.push(own);
                     aval.push(grp);
                     aval.extend(acl);
                     SmbcXAttrValue::AclAll(aval)
                 })));

/// Parse a system.nt_sec_desc.* call to an XAttrValue
named!(nt_sec_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(xattr: alt!(exact!(nt_sec_num_xattr_parse) | exact!(nt_sec_name_xattr_parse))
                 >> (xattr)));

/// Parse a numeric system.nt_sec_desc.* call to a Vec SmbcAclValue
named!(nt_sec_num_all_parse(CompleteByteSlice<'_>) -> Vec<SmbcAclValue>,
       do_parse!(rev: revision_all_parse
                 >> tag!(",")
                 >> own: owner_all_parse
                 >> tag!(",")
                 >> grp: group_all_parse
                 >> tag!(",")
                 >> acl: ace_all_parse
                 >> ({
                     let mut aval: Vec<SmbcAclValue> = vec![];
                     aval.push(rev);
                     aval.push(own);
                     aval.push(grp);
                     aval.extend(acl);
                     aval
                 })));

/// Parse a named system.nt_sec_desc.* call to a Vec SmbcAclValue
named!(nt_sec_name_all_parse(CompleteByteSlice<'_>) -> Vec<SmbcAclValue>,
       do_parse!(rev: revision_all_parse
                 >> tag!(",")
                 >> own: owner_all_parse
                 >> grp: group_all_parse
                 >> acl: ace_all_parse
                 >> ({
                     let mut aval: Vec<SmbcAclValue> = vec![];
                     aval.push(rev);
                     aval.push(own);
                     aval.push(grp);
                     aval.extend(acl);
                     aval
                 })));

/// Parse  a system.nt_sec_desc.* call to a Vec SmbcAclValue
named!(nt_sec_all_parse(CompleteByteSlice<'_>) -> Vec<SmbcAclValue>,
       do_parse!(val: alt!(nt_sec_num_all_parse | nt_sec_name_all_parse) >> (val)));

///For named individual SID's (from Owner+, Group+)
named!(read_string(CompleteByteSlice<'_>) -> String,
       do_parse!(sid: alt!(many_till!(anychar, tag!(",")) | many_till!(anychar, eof!()))
                 >> (sid.0.iter().collect::<String>())));

/// Parse a specific ACL into an ACE
named!(ace_parse(CompleteByteSlice<'_>) -> ACE,
       do_parse!(sid: take_until!(":")
                 >> tag!(":")
                 >> atype: aceatype_parse
                 >> tag!("/")
                 >> aflag: aceflag_parse
                 >> tag!("/")
                 >> amask: xattrmask_parse
                 >> (match sid_parse(sid) {
                     Ok((_, s)) => ACE::Numeric(SidType::Numeric(Some(s)), atype, aflag, amask),
                     Err(_) => {
                         let str_sid = from_utf8(sid.as_bytes()).unwrap().to_string();
                         let mask = format!("{}", amask);
                         ACE::Named(SidType::Named(Some(str_sid)), atype, aflag, mask)
                     }
                 })));

/// Parse a specific ACL from system.* or nt_sec_desc.* into an SmbcAclValue
named!(acl_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(tag!("ACL:")
                 >> ace: ace_parse
                 >> (match ace {
                     ACE::Named(..) => SmbcAclValue::AclPlus(ace),
                     ACE::Numeric(..) => SmbcAclValue::Acl(ace),
                 })));

/// parse a list of ACL's (from nt_sec_desc.* or system.*) into a Vec SmbcAclValue
named!(ace_all_parse(CompleteByteSlice<'_>) -> Vec<SmbcAclValue>,
       do_parse!(aces: separated_list!(tag!(","), acl_parse) >> (aces)));

/// Parse a specific ACL into an SmbcAclValue (from .acl:Sid or acl.*)
named!(aclsid_parse(CompleteByteSlice<'_>) -> SmbcAclValue,
       do_parse!(ace: ace_parse
                 >> (match ace {
                     ACE::Named(..) => SmbcAclValue::AclPlus(ace),
                     ACE::Numeric(..) => SmbcAclValue::Acl(ace),
                 })));

/// parse a list of ACL's (acl.*) into a Vec SmbcAclValue
named!(aceall_xattr_parse(CompleteByteSlice<'_>) -> Vec<SmbcAclValue>,
       do_parse!(aces: exact!(separated_list!(tag!(","), aclsid_parse)) >> (aces)));

named!(acestat_parse(CompleteByteSlice<'_>) -> ACE,
       do_parse!(atype: aceatype_parse
                 >> tag!("/")
                 >> aflag: aceflag_parse
                 >> tag!("/")
                 >> amask: xattrmask_parse
                 >> (ACE::Numeric(SidType::Numeric(None), atype, aflag, amask))));

/// parse an individual ace from acl:sid into a SmbcXAttrValue
named!(ace_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(ace: exact!(acestat_parse) >> (SmbcXAttrValue::Ace(ace))));

/// Parse a list of ACL's from (acl.*) into an SmbcXAttrValue
named!(acl_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(aces: exact!(aceall_xattr_parse) >> (SmbcXAttrValue::AclAll(aces))));

/// Parse a numeric SID (Owner, Group call) to an SmbcXAttrValue
named!(sid_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(sid: exact!(sid_parse) >> (SmbcXAttrValue::Sid(sid))));

/// Parse an individual #_time, revision, or inode attribute into a SmbcXAttrValue
named!(unsigned_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(n: exact!(dec_num) >> (SmbcXAttrValue::Unsigned(n))));

/// Parse an a_time for a .* call
named!(atime_all_parse(CompleteByteSlice<'_>) -> SmbcDosValue,
       do_parse!(tag!("A_TIME:") >> n: dec_num >> (SmbcDosValue::ATime(n))));

/// Parse an m_time for a .* call
named!(mtime_all_parse(CompleteByteSlice<'_>) -> SmbcDosValue,
       do_parse!(tag!("M_TIME:") >> n: dec_num >> (SmbcDosValue::MTime(n))));

/// Parse a c_time for a .* call
named!(ctime_all_parse(CompleteByteSlice<'_>) -> SmbcDosValue,
       do_parse!(tag!("C_TIME:") >> n: dec_num >> (SmbcDosValue::CTime(n))));

/// Parse an inode for a .* call
named!(inode_all_parse(CompleteByteSlice<'_>) -> SmbcDosValue,
       do_parse!(tag!("INODE:") >> n: dec_num >> (SmbcDosValue::INode(n))));

/// Parse a signed individual xattr value (aka .size)
named!(signed_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(n: exact!(sdec_num) >> (SmbcXAttrValue::Signed(n))));

/// Parse a size for a .* call
named!(size_all_parse(CompleteByteSlice<'_>) -> SmbcDosValue,
       do_parse!(tag!("SIZE:") >> n: sdec_num >> (SmbcDosValue::Size(n))));

/// Parse a dos_attr.* call
named!(dos_xattr_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(mode: mode_all_parse
                 >> tag!(",")
                 >> size: size_all_parse
                 >> tag!(",")
                 >> atime: atime_all_parse
                 >> tag!(",")
                 >> mtime: mtime_all_parse
                 >> tag!(",")
                 >> ctime: ctime_all_parse
                 >> tag!(",")
                 >> inode: inode_all_parse
                 >> (SmbcXAttrValue::DosAll(vec![mode, size, atime, mtime, ctime, inode]))));

/// Parse all dos attr for a system.* call
named!(dos_all_parse(CompleteByteSlice<'_>) -> Vec<SmbcDosValue>,
       do_parse!(mode: mode_all_parse
                 >> tag!(",")
                 >> size: size_all_parse
                 >> tag!(",")
                 >> atime: atime_all_parse
                 >> tag!(",")
                 >> mtime: mtime_all_parse
                 >> tag!(",")
                 >> ctime: ctime_all_parse
                 >> tag!(",")
                 >> inode: inode_all_parse
                 >> (vec![mode, size, atime, mtime, ctime, inode])));

/// Parse a system.* call
named!(system_all_parse(CompleteByteSlice<'_>) -> SmbcXAttrValue,
       do_parse!(nt: nt_sec_all_parse
                 >> tag!(",")
                 >> dos: dos_all_parse
                 >> (SmbcXAttrValue::All(nt, dos))));

/// Parse any getxattr valye to SmbcXattrValue
named!(pub xattr_parser(CompleteByteSlice<'_>) -> SmbcXAttrValue,
    do_parse!(
        xattr: alt!(
            system_all_parse |
            dos_xattr_parse |
            nt_sec_xattr_parse |
            mode_xattr_parse |
            sid_xattr_parse |
            ace_xattr_parse |
            unsigned_xattr_parse |
            signed_xattr_parse |
            acl_xattr_parse |
            sidplus_xattr_parse
        ) >>
        (
            xattr
        )
    )
);
