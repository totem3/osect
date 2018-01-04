#![allow(dead_code,unused_imports)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[macro_use(u32,tag,do_parse,call,map,flat_map,map_res,count,count_fixed,error_position,many0,many1,named,char)]
extern crate nom;
use nom::{HexDisplay,Offset,Needed,IResult,ErrorKind,le_i8,le_u8,le_u64,le_u32,le_i32,anychar,digit};
use nom::Err;
use std::fs::File;
use std::io::Read;

static INPUT:[u8;32] = [0xcfu8,0xfa,0xed,0xfe,0x07,0x00,0x00,0x01,0x03,0x00,0x00,0x80,0x02,0x00,0x00,0x00,0x1a,0x00,0x00,0x00,0x90,0x0b,0x00,0x00,0x85,0x00,0x20,0x00,0x00,0x00,0x00,0x00];

pub fn header(input:&[u8]) -> IResult<&[u8], mach_header_64> {
    do_parse!(input,
        magic: le_u32 >>
        cputype: le_i32 >>
        cpusubtype: le_i32 >>
        filetype: le_u32 >>
        ncmds: le_u32 >>
        sizeofcmds: le_u32 >>
        flags: le_u32 >>
        reserved: le_u32 >>
      (mach_header_64{magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved})
    )
}

pub fn segment_command(input:&[u8]) -> IResult<&[u8], segment_command_64> {
    do_parse!(input,
        cmd: le_u32 >>
        cmdsize: le_u32 >>
        segname: count_fixed!( ::std::os::raw::c_char, le_i8, 16) >>
        vmaddr: le_u64 >>
        vmsize: le_u64 >>
        fileoff: le_u64 >>
        filesize: le_u64 >>
        maxprot: le_i32 >>
        initprot: le_i32 >>
        nsects: le_u32 >>
        flags: le_u32 >>
      (segment_command_64{cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags})
    )
}

pub enum Segment {
    RoutinesCommand(routines_command),
    EncryptionInfoCommand(encryption_info_command),
    SegmentCommand(segment_command),
    RoutinesCommand64(routines_command_64),
    EncryptionInfoCommand64(encryption_info_command_64),
    SegmentCommand64(segment_command_64),
    FvmlibCommand(fvmlib_command),
    DylibCommand(dylib_command),
    SubFrameworkCommand(sub_framework_command),
    SubClientCommand(sub_client_command),
    SubUmbrellaCommand(sub_umbrella_command),
    SubLibraryCommand(sub_library_command),
    PreboundDylibCommand(prebound_dylib_command),
    DylinkerCommand(dylinker_command),
    ThreadCommand(thread_command),
    SymtabCommand(symtab_command),
    DysymtabCommand(dysymtab_command),
    TwolevelHintsCommand(twolevel_hints_command),
    PrebindCksumCommand(prebind_cksum_command),
    UuidCommand(uuid_command),
    RpathCommand(rpath_command),
    LinkeditDataCommand(linkedit_data_command),
    VersionMinCommand(version_min_command),
    BuildVersionCommand(build_version_command),
    DyldInfoCommand(dyld_info_command),
    LinkerOptionCommand(linker_option_command),
    SymsegCommand(symseg_command),
    IdentCommand(ident_command),
    FvmfileCommand(fvmfile_command),
    EntryPointCommand(entry_point_command),
    SourceVersionCommand(source_version_command),
    NoteCommand(note_command),
}

macro_rules! command_parser {
    ($i:expr, 25) => {parse_segment_command($i)};
}

pub fn parse_command(input: &[u8]) -> IResult<&[u8], Segment> {
   do_parse!(input,
       cmd: le_u32 >>
       body: command_parser!(cmd) >>
       (body)
   )
}

pub fn gen_command_parser(input: &[u8]) -> fn(&[u8]) -> IResult<&[u8], Segment> {
    return parse_segment_command;
}

pub fn parse_segment_command(input: &[u8]) -> IResult<&[u8], Segment> {
    do_parse!(input,
        cmdsize: le_u32 >>
        segname: count_fixed!(::std::os::raw::c_char, le_i8, 16) >>
        vmaddr: le_u64 >>
        vmsize: le_u64 >>
        fileoff: le_u64 >>
        filesize: le_u64 >>
        maxprot: le_i32 >>
        initprot: le_i32 >>
        nsects: le_u32 >>
        flags: le_u32 >>
        (Segment::SegmentCommand64(segment_command_64{cmd: LC_SEGMENT_64, cmdsize: cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags}))
    )
}

pub fn section(input:&[u8]) -> IResult<&[u8], section_64> {
    do_parse!(input,
        sectname: count_fixed!( ::std::os::raw::c_char, le_i8, 16) >>
        segname: count_fixed!( ::std::os::raw::c_char, le_i8, 16) >>
        addr: le_u64 >>
        size: le_u64 >>
        offset: le_u32 >>
        align: le_u32 >>
        reloff: le_u32 >>
        nreloc: le_u32 >>
        flags: le_u32 >>
        reserved1: le_u32 >>
        reserved2: le_u32 >>
        reserved3: le_u32 >>
      (section_64{sectname, segname, addr, size, offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3})
    )
}

fn main() {
    let path = "target/debug/osect";
    let mut file = File::open(path).unwrap();
    let mut vec = vec![];
    let _ = file.read_to_end(&mut vec);

    let header = header(&INPUT);
    println!("{:?}", header.unwrap());
}

#[cfg]
mod test {
    static INPUT:[u8;32] = [0xcfu8,0xfa,0xed,0xfe,0x07,0x00,0x00,0x01,0x03,0x00,0x00,0x80,0x02,0x00,0x00,0x00,0x1a,0x00,0x00,0x00,0x90,0x0b,0x00,0x00,0x85,0x00,0x20,0x00,0x00,0x00,0x00,0x00];
    #[test]
    fn test_parse_segment_command() {
        
    }
}
