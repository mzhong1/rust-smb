use crate::smbc::*;
use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case, take_until, take_while1};
use nom::character::complete::anychar;
use nom::character::{is_digit, is_hex_digit};
use nom::combinator::{all_consuming, eof, map, map_opt, map_res, opt, value};
use nom::multi::{many_till, separated_list0};
use nom::{IResult, Parser};
use std::convert::TryFrom;

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
    assert_eq!(all_consuming(hex_num)(bytes).unwrap().1, 128_108_i32);
}

#[test]
fn test_dec_num() {
    let test = "12345".to_string();
    let bytes = test.as_bytes();
    assert_eq!(all_consuming(dec_num)(bytes).unwrap().1, 12345);
}

#[test]
fn test_list_dash() {
    let test = "1-2-3-45".to_string();
    let bytes = test.as_bytes();
    all_consuming(list_dash)(bytes).unwrap();
}

#[test]
fn test_sid_parse() {
    let test = "S-1-22-2-1001".to_string();
    let sid = test.as_bytes();
    all_consuming(sid_parse)(sid).unwrap();
}

#[test]
fn test_xattrmask_parse() {
    let testmode = "0x001f01ff".to_string();
    let modebytes = testmode.as_bytes();

    all_consuming(xattrmask_parse)(modebytes).unwrap();
}

#[test]
fn test_aceflag_parse() {
    let testaflags = "11".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceflag_parse)(aflagbytes).unwrap();
    let testaflags = "8".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceflag_parse)(aflagbytes).unwrap();
    let testaflags = "7".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceflag_parse)(aflagbytes).unwrap();
    let testaflags = "1".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceflag_parse)(aflagbytes).unwrap();
    let testaflags = "0".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceflag_parse)(aflagbytes).unwrap();
}

#[test]
fn test_bool_num() {
    let testaflags = "7".to_string();
    let aflagbytes = testaflags.as_bytes();
    println!("Test bool_num {:?}", bool_num(aflagbytes).unwrap_err());
    let testaflags = "1".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(bool_num)(aflagbytes).unwrap();
    let testaflags = "0".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(bool_num)(aflagbytes).unwrap();
}

#[test]
fn test_aceatype_parse() {
    let testaflags = "7".to_string();
    let aflagbytes = testaflags.as_bytes();
    println!("Test aceatype_parse {:?}", aceatype_parse(aflagbytes).unwrap_err());
    let testaflags = "0".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceatype_parse)(aflagbytes).unwrap();
    let testaflags = "1".to_string();
    let aflagbytes = testaflags.as_bytes();
    all_consuming(aceatype_parse)(aflagbytes).unwrap();
}

#[test]
fn test_ace_parse() {
    let test = "S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test ace parse {:?}", ace_parse(bytes).unwrap());

    let test = "Unix Group\\adm:0/3/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test ace parse {:?}", ace_parse(bytes).unwrap());
    let test = "\\Everyone:0/0/0x00120089".to_string();
    let bytes = test.as_bytes();
    println!("Test ace parse {:?}", ace_parse(bytes).unwrap());
}

#[test]
fn test_acl_parse() {
    let test = "ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test acl parse {:?}", acl_parse(bytes).unwrap());

    let test = "ACL:Unix Group\\adm:0/3/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    println!("Test acl parse {:?}", acl_parse(bytes).unwrap());
    let test = "ACL:\\Everyone:0/0/0x00120089".to_string();
    let bytes = test.as_bytes();
    println!("Test acl parse {:?}", acl_parse(bytes).unwrap());
}

#[test]
fn test_dosmode_parse() {
    let test = "0x20".to_string();
    let bytes = test.as_bytes();
    assert_eq!(dosmode_parse(bytes).unwrap(), (&[] as &[u8], DosMode::ARCHIVE));
}

#[test]
fn test_mode_xattr_parse() {
    let test = "0x20".to_string();
    let bytes = test.as_bytes();
    let mode = mode_xattr_parse(bytes).unwrap().1;
    println!("Test modexattr {:?}", mode);
}

#[test]
fn test_mode_all_parse() {
    let test = "MODE:0x20".to_string();
    let bytes = test.as_bytes();
    let mode = mode_all_parse(bytes).unwrap().1;
    println!("Test modexattr {:?}", mode);
}

#[test]
fn test_groupplus_all_parse() {
    let test = "GROUP:Unix Group\\superuser123".to_string();
    let bytes = test.as_bytes();
    let mode = groupplus_all_parse(bytes).unwrap().1;
    println!("Test groupplus all parse {:?}", mode);
    let test = "GROUP:TESTING\\superuser123,".to_string();
    let bytes = test.as_bytes();
    let mode = groupplus_all_parse(bytes).unwrap().1;
    println!("Test groupplus all parse {:?}", mode);
}

#[test]
fn test_groupsid_all_parse() {
    let test = "GROUP:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = groupsid_all_parse(bytes).unwrap().1;
    println!("Test groupsid all parse {:?}", mode);
}

#[test]
fn test_group_all_parse() {
    let test = "GROUP:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = group_all_parse(bytes).unwrap().1;
    println!("Test group all parse {:?}", mode);
    let test = "GROUP:Unix Group\\superuser123,".to_string();
    let bytes = test.as_bytes();
    let mode = group_all_parse(bytes).unwrap().1;
    println!("Test group all parse {:?}", mode);
}

#[test]
fn test_ownerplus_all_parse() {
    let test = "OWNER:TESTING\\superuser123".to_string();
    let bytes = test.as_bytes();
    let mode = ownerplus_all_parse(bytes).unwrap().1;
    println!("Test ownerplus all parse {:?}", mode);
    let test = "OWNER:TESTING\\superuser123,OWNER:Testing".to_string();
    let bytes = test.as_bytes();
    let mode = ownerplus_all_parse(bytes).unwrap().1;
    println!("Test ownerplus all parse {:?}", mode);
}

#[test]
fn test_ownersid_all_parse() {
    let test = "OWNER:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = ownersid_all_parse(bytes).unwrap().1;
    println!("Test ownersid all parse {:?}", mode);
}

#[test]
fn test_owner_all_parse() {
    let test = "OWNER:TESTING\\superuser123".to_string();
    let bytes = test.as_bytes();
    let mode = owner_all_parse(bytes).unwrap().1;
    println!("Test owner all parse {:?}", mode);
    let test = "OWNER:S-1-2-22-4".to_string();
    let bytes = test.as_bytes();
    let mode = owner_all_parse(bytes).unwrap().1;
    println!("Test owner all parse {:?}", mode);
}

#[test]
fn test_revision_all_parse() {
    let test = "REVISION:1".to_string();
    let bytes = test.as_bytes();
    let rev = revision_all_parse(bytes).unwrap().1;
    println!("Test revision all parse {:?}", rev)
}

#[test]
fn test_nt_sec_num_xattr_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_num_xattr_parse(bytes).unwrap().1;
    println!("Test nt sec num xattr parse {:?}", val);
}

#[test]
fn test_nt_sec_name_xattr_parse() {
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_name_xattr_parse(bytes).unwrap().1;
    println!("Test nt sec name xattr parse {:?}", val);
}

#[test]
fn test_nt_sec_xattr_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_xattr_parse(bytes).unwrap().1;
    println!("Test nt sec xattr parse {:?}", val);
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_xattr_parse(bytes).unwrap().1;
    println!("Test nt sec xattr parse {:?}", val);
}

#[test]
fn test_nt_sec_num_all_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_num_all_parse(bytes).unwrap().1;
    println!("Test nt sec num all parse {:?}", val);
}

#[test]
fn test_nt_sec_name_all_parse() {
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_name_all_parse(bytes).unwrap().1;
    println!("Test nt sec name all parse {:?}", val);
}

#[test]
fn test_nt_sec_all_parse() {
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_all_parse(bytes).unwrap().1;
    println!("Test nt sec all parse {:?}", val);
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = nt_sec_all_parse(bytes).unwrap().1;
    println!("Test nt sec all parse {:?}", val);
}

#[test]
fn test_read_string() {
    let test = "asdousajhfb12323525184328,99999".to_string();
    let bytes = test.as_bytes();
    let val = read_string(bytes).unwrap().1;
    println!("Test read string {:?}", val);
    let test = "asdousa jhfb 12323525184328 99999".to_string();
    let bytes = test.as_bytes();
    let val = read_string(bytes).unwrap().1;
    println!("Test read string {:?}", val);
}

#[test]
fn test_ace_all_parse() {
    let test = "ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = ace_all_parse(bytes).unwrap().1;
    println!("Test ace all_parse {:?}", val);
    let test = "ACL:\\Everyone:0/0/0x001f01ff,ACL:Unix Group\\adm:0/0/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f01ff,ACL:TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = ace_all_parse(bytes).unwrap().1;
    println!("Test ace all_parse {:?}", val);
}

#[test]
fn test_acl_xattr_parse() {
    let test = "S-1-1-0:0/0/0x001f01ff,S-1-22-2-4:0/0/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = acl_xattr_parse(bytes).unwrap().1;
    println!("Test acl xattr_parse {:?}", val);
    let test = "\\Everyone:0/0/0x001f01ff,Unix Group\\adm:0/0/0x001f01ff,Unix Group\\superuser123:0/0/0x001f01ff,TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = acl_xattr_parse(bytes).unwrap().1;
    println!("Test acl xattr_parse {:?}", val);
}

#[test]
fn test_aclsid_parse() {
    let test = "S-1-1-0:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aclsid_parse(bytes).unwrap().1;
    println!("Test aclsid_parse {:?}", val);
    let test = "Unix Group\\adm:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aclsid_parse(bytes).unwrap().1;
    println!("Test aclsid_parse {:?}", val);
}

#[test]
fn test_aceall_xattr_parse() {
    let test = "S-1-1-0:0/0/0x001f01ff,S-1-22-2-4:0/0/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aceall_xattr_parse(bytes).unwrap().1;
    println!("Test aceall xattr_parse {:?}", val);
    let test = "\\Everyone:0/0/0x001f01ff,Unix Group\\adm:0/0/0x001f01ff,Unix Group\\superuser123:0/0/0x001f01ff,TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = aceall_xattr_parse(bytes).unwrap().1;
    println!("Test aceall xattr_parse {:?}", val);
}

#[test]
fn test_sid_xattr_parse() {
    let test = "S-1-1-0".to_string();
    let bytes = test.as_bytes();
    let val = sid_xattr_parse(bytes).unwrap().1;
    println!("Test sid_xattr_parse {:?}", val);
}

#[test]
fn test_unsigned_xattr_parse() {
    let test = "15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = unsigned_xattr_parse(bytes).unwrap().1;
    println!("Test unsigned_xattr_parse {:?}", val);
    let test = "0".to_string();
    let bytes = test.as_bytes();
    let val = unsigned_xattr_parse(bytes).unwrap().1;
    println!("Test unsigned_xattr_parse {:?}", val);
}

#[test]
fn test_atime_all_parse() {
    let test = "A_TIME:15123213".to_string();
    let bytes = test.as_bytes();
    let val = atime_all_parse(bytes).unwrap().1;
    println!("Test atime_all_parse {:?}", val);
}

#[test]
fn test_mtime_all_parse() {
    let test = "M_TIME:15123213".to_string();
    let bytes = test.as_bytes();
    let val = mtime_all_parse(bytes).unwrap().1;
    println!("Test mtime_all_parse {:?}", val);
}

#[test]
fn test_ctime_all_parse() {
    let test = "C_TIME:15123213".to_string();
    let bytes = test.as_bytes();
    let val = ctime_all_parse(bytes).unwrap().1;
    println!("Test ctime_all_parse {:?}", val);
}

#[test]
fn test_inode_all_parse() {
    let test = "INODE:15".to_string();
    let bytes = test.as_bytes();
    let val = inode_all_parse(bytes).unwrap().1;
    println!("Test inode_all_parse {:?}", val);
}

#[test]
fn test_sdec_num() {
    let test = "12345".to_string();
    let bytes = test.as_bytes();
    sdec_num(bytes).unwrap();
    let test = "-12345".to_string();
    let bytes = test.as_bytes();
    sdec_num(bytes).unwrap();
}

#[test]
fn test_signed_xattr_parse() {
    let test = "-15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = signed_xattr_parse(bytes).unwrap().1;
    println!("Test signed_xattr_parse {:?}", val);
    let test = "1230".to_string();
    let bytes = test.as_bytes();
    let val = signed_xattr_parse(bytes).unwrap().1;
    println!("Test signed_xattr_parse {:?}", val);
}

#[test]
fn test_size_all_parse() {
    let test = "SIZE:15".to_string();
    let bytes = test.as_bytes();
    let val = size_all_parse(bytes).unwrap().1;
    println!("Test size_all_parse {:?}", val);
    let test = "SIZE:-15".to_string();
    let bytes = test.as_bytes();
    let val = size_all_parse(bytes).unwrap().1;
    println!("Test size_all_parse {:?}", val);
}

#[test]
fn test_dos_xattr_parse() {
    let test =
        "MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825"
            .to_string();
    let bytes = test.as_bytes();
    let val = dos_xattr_parse(bytes).unwrap().1;
    println!("Test dos_xattr_parse {:?}", val);
}

#[test]
fn test_dos_all_parse() {
    let test =
        "MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825"
            .to_string();
    let bytes = test.as_bytes();
    let val = dos_all_parse(bytes).unwrap().1;
    println!("Test dos_all_parse {:?}", val);
}

#[test]
fn test_system_all_parse() {
    let test = "REVISION:1,OWNER:S-1-22-2-4,GROUP:S-1-22-2-1001,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = system_all_parse(bytes).unwrap().1;
    println!("Test system_all_parse {:?}", val);
    let test = "REVISION:1,OWNER:Unix Group\\adm,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x001f01ff,ACL:Unix Group\\adm:0/0/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f01ff,ACL:TESTING\\superuser123:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = system_all_parse(bytes).unwrap().1;
    println!("Test system_all_parse {:?}", val);
}

#[test]
fn test_sidplus_xattr_parse() {
    let test = "\\Everyone".to_string();
    let bytes = test.as_bytes();
    let val = sidplus_xattr_parse(bytes).unwrap().1;
    println!("Test sidplus xattr parse {:?}", val);
}

#[test]
fn test_ace_xattr_parse() {
    let test = "0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = ace_xattr_parse(bytes).unwrap().1;
    println!("Test ace xattr parse {:?}", val);
}

#[test]
fn test_acestat_parse() {
    let test = "0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = acestat_parse(bytes).unwrap().1;
    println!("Test ace stat parse {:?}", val);
}

#[test]
fn test_xattr_parser() {
    //System.*
    let test = "REVISION:1,OWNER:S-1-22-2-4,GROUP:S-1-22-2-1001,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser System.* {:?}", val);
    let test = "REVISION:1,OWNER:Unix Group\\adm,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x001f01ff,ACL:Unix Group\\adm:0/0/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f01ff,ACL:TESTING\\superuser123:0/0/0x001f01ff,MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser System.* {:?}", val);
    //Dos_Attr.*
    let test =
        "MODE:0x20,SIZE:0,A_TIME:1543337349,M_TIME:1543337349,C_TIME:1543337349,INODE:393825"
            .to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Dos_Attr.* {:?}", val);
    //Acl.*
    let test = "\\Everyone:0/0/0x001f01ff,Unix Group\\adm:0/0/0x001f01ff,Unix Group\\superuser123:0/0/0x001f01ff,TESTING\\superuser123:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Acl.* {:?}", val);
    let test = "S-1-1-0:0/0/0x001f01ff,S-1-22-2-4:0/0/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Acl.* {:?}", val);
    //Nt_Sec_Desc.*
    let test = "REVISION:1,OWNER:S-1-5-21-3568127003-813371847-2250217916-1001,GROUP:S-1-22-2-4,ACL:S-1-1-0:0/0/0x001f01ff,ACL:S-1-22-2-4:0/0/0x001f01ff,ACL:S-1-22-2-1001:0/0/0x001f01ff,ACL:S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff"
        .to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Nt_Sec_Desc.* {:?}", val);
    let test = "REVISION:1,OWNER:TESTING\\superuser123,GROUP:Unix Group\\superuser123,ACL:\\Everyone:0/0/0x00120089,ACL:Unix Group\\adm:0/3/0x001f01ff,ACL:Unix Group\\superuser123:0/0/0x001f019f,ACL:TESTING\\superuser123:0/0/0x001f019f".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Nt_sec_Desc.* {:?}", val);
    //.acl:Sid
    let test = "0/0/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Acl:SID {:?}", val);
    //.group | .owner
    let test = "S-1-1-0-123123213".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser SID {:?}", val);
    //.group+ | .owner+
    let test = "Unix Group\\superuser123".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser SIDSTRING {:?}", val);
    //revision | a_time | c_time | m_time | inode | (sometimes size)
    let test = "15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser USIGN {:?}", val);
    let test = "0".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser USIGN {:?}", val);
    //mode
    let test = "0x20".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser MODE {:?}", val);
    let test = "0x31".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser MODE {:?}", val);
    //size, granted, it would only work for negative size values...which would never happen...
    let test = "-15123213234234".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser ISIGN {:?}", val);
    let test = "S-1-1-0:0/11/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser sid {:?}", val);

    let test = "S-1-5-21-3568127003-813371847-2250217916-1001:0/0/0x001f01ff,S-1-3-0:0/11/0x001f01ff,S-1-22-2-1001:0/0/0x001f01ff,S-1-3-1:0/11/0x001f01ff,S-1-1-0:0/3/0x001f01ff".to_string();
    let bytes = test.as_bytes();
    let val = xattr_parser(bytes).unwrap().1;
    println!("Test xattr_parser Dir ACLS {:?}", val);
}

/// Parse a decimal number
fn dec_num(input: &[u8]) -> IResult<&[u8], u64> {
    map_res(take_while1(is_digit), |n: &[u8]| {
        let s = String::from_utf8_lossy(n);
        s.parse()
    })(input)
}

/// Parse a signed decimal number
fn sdec_num(input: &[u8]) -> IResult<&[u8], i64> {
    map_res(opt(tag("-")).and(dec_num), |(sign, n): (Option<&[u8]>, u64)| {
        i64::try_from(n).map(|r| r * sign.map_or(1, |_| -1))
    })(input)
}

/// Parse a Hex number
fn hex_num(input: &[u8]) -> IResult<&[u8], i32> {
    map_res(take_while1(is_hex_digit), |n: &[u8]| {
        let s = String::from_utf8_lossy(n);
        i32::from_str_radix(&s, 16)
    })(input)
}

/// Parse an XAttrMask
fn xattrmask_parse(input: &[u8]) -> IResult<&[u8], XAttrMask> {
    let (input, _) = tag("0x")(input)?;
    map_opt(hex_num, XAttrMask::from_bits)(input)
}

/// Parse an AceFlag
fn aceflag_parse(input: &[u8]) -> IResult<&[u8], AceFlag> {
    map_res(dec_num, |num| AceFlag::from_bits(num as i32).ok_or(()))(input)
}

/// parse a binary number (0 or 1 only)
fn bool_num(input: &[u8]) -> IResult<&[u8], i32> {
    alt((value(0, tag("0")), value(1, tag("1"))))(input)
}

/// Parse an AceAtype
fn aceatype_parse(input: &[u8]) -> IResult<&[u8], AceAtype> {
    map(bool_num, |num| match num {
        1 => AceAtype::DENIED,
        0 => AceAtype::ALLOWED,
        _ => AceAtype::ALLOWED,
    })(input)
}

/// Parse a DosMode
fn dosmode_parse(input: &[u8]) -> IResult<&[u8], DosMode> {
    let (input, _) = tag("0x")(input)?;
    map_opt(hex_num, DosMode::from_bits)(input)
}

/// Individual mode get parse
fn mode_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(dosmode_parse), SmbcXAttrValue::Mode)(input)
}

/// Mode parse for .* call
fn mode_all_parse(input: &[u8]) -> IResult<&[u8], SmbcDosValue> {
    let (input, _) = tag_no_case("MODE:")(input)?;
    map(dosmode_parse, SmbcDosValue::MODE)(input)
}

/// collect numbers seperated by -
fn list_dash(input: &[u8]) -> IResult<&[u8], Vec<u64>> {
    separated_list0(tag("-"), dec_num)(input)
}

/// Parse a numeric SID
pub fn sid_parse(input: &[u8]) -> IResult<&[u8], Sid> {
    let (input, _) = tag("S-1-")(input)?;
    map(list_dash, Sid)(input)
}

/// Parse a named SID
fn sidplus_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(read_string), SmbcXAttrValue::SidPlus)(input)
}

/// Parse a named SID for Group+ (.* call)
fn groupplus_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    let (input, _) = tag("GROUP:")(input)?;
    map(read_string, SmbcAclValue::GroupPlus)(input)
}

/// Parse a numeric SID for Group (.* call)
fn groupsid_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    let (input, _) = tag("GROUP:")(input)?;
    map(sid_parse, SmbcAclValue::Group)(input)
}

/// parse a SID for Group(+) (.* call)
fn group_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    alt((groupsid_all_parse, groupplus_all_parse))(input)
}

/// Parse an SID for Owner+ (.* call)
fn ownerplus_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    let (input, _) = tag("OWNER:")(input)?;
    map(read_string, SmbcAclValue::OwnerPlus)(input)
}

/// Parse an SID for Owner (.* call)
fn ownersid_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    let (input, _) = tag("OWNER:")(input)?;
    map(sid_parse, SmbcAclValue::Owner)(input)
}

/// Parse an SID for Owner(+) (.* call)
fn owner_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    alt((ownersid_all_parse, ownerplus_all_parse))(input)
}

/// Parse a num for Revision (.* call)
fn revision_all_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    let (input, _) = tag("REVISION:")(input)?;
    map(dec_num, SmbcAclValue::Revision)(input)
}

/// Parse a numeric system.nt_sec_desc.* call to an XAttrValue
fn nt_sec_num_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    let (input, rev) = revision_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, own) = owner_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, grp) = group_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, acl) = ace_all_parse(input)?;

    let mut aval = vec![rev, own, grp];
    aval.extend(acl);
    Ok((input, SmbcXAttrValue::AclAll(aval)))
}

/// Parse a named system.nt_sec_desc.*+ call to an XAttrValue
fn nt_sec_name_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    let (input, rev) = revision_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, own) = owner_all_parse(input)?;
    let (input, grp) = group_all_parse(input)?;
    let (input, acl) = ace_all_parse(input)?;

    let mut aval: Vec<SmbcAclValue> = vec![rev, own, grp];
    aval.extend(acl);
    Ok((input, SmbcXAttrValue::AclAll(aval)))
}

/// Parse a system.nt_sec_desc.* call to an XAttrValue
fn nt_sec_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    alt((all_consuming(nt_sec_num_xattr_parse), all_consuming(nt_sec_name_xattr_parse)))(input)
}

/// Parse a numeric system.nt_sec_desc.* call to a Vec SmbcAclValue
fn nt_sec_num_all_parse(input: &[u8]) -> IResult<&[u8], Vec<SmbcAclValue>> {
    let (input, rev) = revision_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, own) = owner_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, grp) = group_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, acl) = ace_all_parse(input)?;
    let mut aval: Vec<SmbcAclValue> = vec![];
    aval.push(rev);
    aval.push(own);
    aval.push(grp);
    aval.extend(acl);
    Ok((input, aval))
}

/// Parse a named system.nt_sec_desc.* call to a Vec SmbcAclValue
fn nt_sec_name_all_parse(input: &[u8]) -> IResult<&[u8], Vec<SmbcAclValue>> {
    let (input, rev) = revision_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, own) = owner_all_parse(input)?;
    let (input, grp) = group_all_parse(input)?;
    let (input, acl) = ace_all_parse(input)?;
    let mut aval: Vec<SmbcAclValue> = vec![];
    aval.push(rev);
    aval.push(own);
    aval.push(grp);
    aval.extend(acl);
    Ok((input, aval))
}
/// Parse  a system.nt_sec_desc.* call to a Vec SmbcAclValue
fn nt_sec_all_parse(input: &[u8]) -> IResult<&[u8], Vec<SmbcAclValue>> {
    alt((nt_sec_num_all_parse, nt_sec_name_all_parse))(input)
}

///For named individual SID's (from Owner+, Group+)
fn read_string(input: &[u8]) -> IResult<&[u8], String> {
    map(alt((many_till(anychar, tag(",")), many_till(anychar, eof))), |sid| {
        sid.0.iter().collect::<String>()
    })(input)
}

/// Parse a specific ACL into an ACE
fn ace_parse(input: &[u8]) -> IResult<&[u8], ACE> {
    let (input, sid) = take_until(":")(input)?;
    let (input, _) = tag(":")(input)?;
    let (input, atype) = aceatype_parse(input)?;
    let (input, _) = tag("/")(input)?;
    let (input, aflag) = aceflag_parse(input)?;
    let (input, _) = tag("/")(input)?;
    let (input, amask) = xattrmask_parse(input)?;
    let result = match sid_parse(sid) {
        Ok((_, s)) => ACE::Numeric(SidType::Numeric(Some(s)), atype, aflag, amask),
        Err(_) => {
            let str_sid = std::str::from_utf8(sid).unwrap().to_string();
            let mask = format!("{}", amask);
            ACE::Named(SidType::Named(Some(str_sid)), atype, aflag, mask)
        }
    };
    Ok((input, result))
}

/// Parse a specific ACL from system.* or nt_sec_desc.* into an SmbcAclValue
fn acl_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    let (input, _) = tag("ACL:")(input)?;
    map(ace_parse, |ace| match ace {
        ACE::Named(..) => SmbcAclValue::AclPlus(ace),
        ACE::Numeric(..) => SmbcAclValue::Acl(ace),
    })(input)
}

/// parse a list of ACL's (from nt_sec_desc.* or system.*) into a Vec SmbcAclValue
fn ace_all_parse(input: &[u8]) -> IResult<&[u8], Vec<SmbcAclValue>> {
    separated_list0(tag(","), acl_parse)(input)
}

/// Parse a specific ACL into an SmbcAclValue (from .acl:Sid or acl.*)
fn aclsid_parse(input: &[u8]) -> IResult<&[u8], SmbcAclValue> {
    map(ace_parse, |ace| match ace {
        ACE::Named(..) => SmbcAclValue::AclPlus(ace),
        ACE::Numeric(..) => SmbcAclValue::Acl(ace),
    })(input)
}

/// parse a list of ACL's (acl.*) into a Vec SmbcAclValue
fn aceall_xattr_parse(input: &[u8]) -> IResult<&[u8], Vec<SmbcAclValue>> {
    all_consuming(separated_list0(tag(","), aclsid_parse))(input)
}

fn acestat_parse(input: &[u8]) -> IResult<&[u8], ACE> {
    let (input, atype) = aceatype_parse(input)?;
    let (input, _) = tag("/")(input)?;
    let (input, aflag) = aceflag_parse(input)?;
    let (input, _) = tag("/")(input)?;
    let (input, amask) = xattrmask_parse(input)?;
    Ok((input, ACE::Numeric(SidType::Numeric(None), atype, aflag, amask)))
}

/// parse an individual ace from acl:sid into a SmbcXAttrValue
fn ace_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(acestat_parse), SmbcXAttrValue::Ace)(input)
}

/// Parse a list of ACL's from (acl.*) into an SmbcXAttrValue
fn acl_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(aceall_xattr_parse), SmbcXAttrValue::AclAll)(input)
}

/// Parse a numeric SID (Owner, Group call) to an SmbcXAttrValue
fn sid_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(sid_parse), SmbcXAttrValue::Sid)(input)
}

/// Parse an individual #_time, revision, or inode attribute into a SmbcXAttrValue
fn unsigned_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(dec_num), SmbcXAttrValue::Unsigned)(input)
}

/// Parse an a_time for a .* call
fn atime_all_parse(input: &[u8]) -> IResult<&[u8], SmbcDosValue> {
    let (input, _) = tag("A_TIME:")(input)?;
    map(dec_num, SmbcDosValue::ATime)(input)
}

/// Parse an m_time for a .* call
fn mtime_all_parse(input: &[u8]) -> IResult<&[u8], SmbcDosValue> {
    let (input, _) = tag("M_TIME:")(input)?;
    map(dec_num, SmbcDosValue::MTime)(input)
}

/// Parse a c_time for a .* call
fn ctime_all_parse(input: &[u8]) -> IResult<&[u8], SmbcDosValue> {
    let (input, _) = tag("C_TIME:")(input)?;
    map(dec_num, SmbcDosValue::CTime)(input)
}

/// Parse an inode for a .* call
fn inode_all_parse(input: &[u8]) -> IResult<&[u8], SmbcDosValue> {
    let (input, _) = tag("INODE:")(input)?;
    map(dec_num, SmbcDosValue::INode)(input)
}

/// Parse a signed individual xattr value (aka .size)
fn signed_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    map(all_consuming(sdec_num), SmbcXAttrValue::Signed)(input)
}

/// Parse a size for a .* call
fn size_all_parse(input: &[u8]) -> IResult<&[u8], SmbcDosValue> {
    let (input, _) = tag("SIZE:")(input)?;
    map(sdec_num, SmbcDosValue::Size)(input)
}

/// Parse a dos_attr.* call
fn dos_xattr_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    let (input, mode) = mode_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, size) = size_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, atime) = atime_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, mtime) = mtime_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, ctime) = ctime_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, inode) = inode_all_parse(input)?;
    Ok((input, SmbcXAttrValue::DosAll(vec![mode, size, atime, mtime, ctime, inode])))
}

/// Parse all dos attr for a system.* call
fn dos_all_parse(input: &[u8]) -> IResult<&[u8], Vec<SmbcDosValue>> {
    let (input, mode) = mode_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, size) = size_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, atime) = atime_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, mtime) = mtime_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, ctime) = ctime_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, inode) = inode_all_parse(input)?;
    Ok((input, vec![mode, size, atime, mtime, ctime, inode]))
}

/// Parse a system.* call
fn system_all_parse(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    let (input, nt) = nt_sec_all_parse(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, dos) = dos_all_parse(input)?;
    Ok((input, SmbcXAttrValue::All(nt, dos)))
}

/// Parse any getxattr valye to SmbcXattrValue
pub fn xattr_parser(input: &[u8]) -> IResult<&[u8], SmbcXAttrValue> {
    alt((
        system_all_parse,
        dos_xattr_parse,
        nt_sec_xattr_parse,
        mode_xattr_parse,
        sid_xattr_parse,
        ace_xattr_parse,
        unsigned_xattr_parse,
        signed_xattr_parse,
        acl_xattr_parse,
        sidplus_xattr_parse,
    ))(input)
}
