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

pub enum LoadCommand {
    SegmentCommand(segment_command),
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
    RoutinesCommand(routines_command),
    RoutinesCommand64(routines_command_64),
    SymtabCommand(symtab_command),
    DysymtabCommand(dysymtab_command),
    TwolevelHintsCommand(twolevel_hints_command),
    PrebindCksumCommand(prebind_cksum_command),
    UuidCommand(uuid_command),
    RpathCommand(rpath_command),
    LinkeditDataCommand(linkedit_data_command),
    EncryptionInfoCommand(encryption_info_command),
    EncryptionInfoCommand_64(encryption_info_command_64),
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
    PlaceHolder,
}

impl ::std::fmt::Display for LoadCommand {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            &LoadCommand::SegmentCommand(_) => writeln!(f, "SegmentCommand"),
            &LoadCommand::SegmentCommand64(_) => writeln!(f, "SegmentCommand64"),
            &LoadCommand::FvmlibCommand(_) => writeln!(f, "FvmlibCommand"),
            &LoadCommand::DylibCommand(_) => writeln!(f, "DylibCommand"),
            &LoadCommand::SubFrameworkCommand(_) => writeln!(f, "SubFrameworkCommand"),
            &LoadCommand::SubClientCommand(_) => writeln!(f, "SubClientCommand"),
            &LoadCommand::SubUmbrellaCommand(_) => writeln!(f, "SubUmbrellaCommand"),
            &LoadCommand::SubLibraryCommand(_) => writeln!(f, "SubLibraryCommand"),
            &LoadCommand::PreboundDylibCommand(_) => writeln!(f, "PreboundDylibCommand"),
            &LoadCommand::DylinkerCommand(_) => writeln!(f, "DylinkerCommand"),
            &LoadCommand::ThreadCommand(_) => writeln!(f, "ThreadCommand"),
            &LoadCommand::RoutinesCommand(_) => writeln!(f, "RoutinesCommand"),
            &LoadCommand::RoutinesCommand64(_) => writeln!(f, "RoutinesCommand64"),
            &LoadCommand::SymtabCommand(_) => writeln!(f, "SymtabCommand"),
            &LoadCommand::DysymtabCommand(_) => writeln!(f, "DysymtabCommand"),
            &LoadCommand::TwolevelHintsCommand(_) => writeln!(f, "TwolevelHintsCommand"),
            &LoadCommand::PrebindCksumCommand(_) => writeln!(f, "PrebindCksumCommand"),
            &LoadCommand::UuidCommand(_) => writeln!(f, "UuidCommand"),
            &LoadCommand::RpathCommand(_) => writeln!(f, "RpathCommand"),
            &LoadCommand::LinkeditDataCommand(_) => writeln!(f, "LinkeditDataCommand"),
            &LoadCommand::EncryptionInfoCommand(_) => writeln!(f, "EncryptionInfoCommand"),
            &LoadCommand::EncryptionInfoCommand_64(_) => writeln!(f, "EncryptionInfoCommand_64"),
            &LoadCommand::VersionMinCommand(_) => writeln!(f, "VersionMinCommand"),
            &LoadCommand::BuildVersionCommand(_) => writeln!(f, "BuildVersionCommand"),
            &LoadCommand::DyldInfoCommand(_) => writeln!(f, "DyldInfoCommand"),
            &LoadCommand::LinkerOptionCommand(_) => writeln!(f, "LinkerOptionCommand"),
            &LoadCommand::SymsegCommand(_) => writeln!(f, "SymsegCommand"),
            &LoadCommand::IdentCommand(_) => writeln!(f, "IdentCommand"),
            &LoadCommand::FvmfileCommand(_) => writeln!(f, "FvmfileCommand"),
            &LoadCommand::EntryPointCommand(_) => writeln!(f, "EntryPointCommand"),
            &LoadCommand::SourceVersionCommand(_) => writeln!(f, "SourceVersionCommand"),
            &LoadCommand::NoteCommand(_) => writeln!(f, "NoteCommand"),
            &LoadCommand::PlaceHolder => writeln!(f, "PlaceHolder"),
        }
    }
}


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

pub fn parse_segment_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        segname: count_fixed!(::std::os::raw::c_char, le_i8, 16) >>
        vmaddr: le_u32 >>
        vmsize: le_u32 >>
        fileoff: le_u32 >>
        filesize: le_u32 >>
        maxprot: le_i32 >>
        initprot: le_i32 >>
        nsects: le_u32 >>
        flags: le_u32 >>
        (LoadCommand::SegmentCommand(segment_command{cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags}))
    )
}

pub fn parse_segment_command_64(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        segname: count_fixed!(::std::os::raw::c_char, le_i8, 16) >>
        vmaddr: le_u64 >>
        vmsize: le_u64 >>
        fileoff: le_u64 >>
        filesize: le_u64 >>
        maxprot: le_i32 >>
        initprot: le_i32 >>
        nsects: le_u32 >>
        flags: le_u32 >>
        (LoadCommand::SegmentCommand64(segment_command_64{cmd, cmdsize, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags}))
    )
}

// pub fn parse_fvmlib_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
// }

pub fn parse_dylib_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        offset: le_u32 >> 
        _name: count!(le_i8, cmdsize as usize) >>
        timestamp: le_u32 >>
        current_version: le_u32 >>
        compatibility_version: le_u32 >>
        (LoadCommand::DylibCommand(dylib_command{cmd, cmdsize, dylib: dylib{name: lc_str{offset}, timestamp, current_version, compatibility_version}}))
    )
}

// pub fn parse_sub_framework_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
// }

// pub fn parse_sub_client_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
// }

// pub fn parse_sub_umbrella_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
// }

// pub fn parse_sub_library_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
// }

// pub fn parse_prebound_dylib_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
// }

pub fn parse_dylinker_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        offset: le_u32 >> 
        _name: count!(le_i8, cmdsize as usize) >>
        (LoadCommand::DylinkerCommand(dylinker_command {
            cmd,
            cmdsize,
            name: lc_str { offset: offset },
        }))
    )
}

pub fn parse_thread_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_routines_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_routines_command_64(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_symtab_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        symoff: le_u32 >>
        nsyms: le_u32 >>
        stroff: le_u32 >>
        strsize: le_u32 >>
        (LoadCommand::SymtabCommand(symtab_command{
            cmd,
            cmdsize,
            symoff,
            nsyms,
            stroff,
            strsize,
        }))
    )
}

pub fn parse_dysymtab_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        ilocalsym: le_u32 >>
        nlocalsym: le_u32 >>
        iextdefsym: le_u32 >>
        nextdefsym: le_u32 >>
        iundefsym: le_u32 >>
        nundefsym: le_u32 >>
        tocoff: le_u32 >>
        ntoc: le_u32 >>
        modtaboff: le_u32 >>
        nmodtab: le_u32 >>
        extrefsymoff: le_u32 >>
        nextrefsyms: le_u32 >>
        indirectsymoff: le_u32 >>
        nindirectsyms: le_u32 >>
        extreloff: le_u32 >>
        nextrel: le_u32 >>
        locreloff: le_u32 >>
        nlocrel: le_u32 >>
        (LoadCommand::DysymtabCommand(dysymtab_command{
            cmd,
            cmdsize,
            ilocalsym,
            nlocalsym,
            iextdefsym,
            nextdefsym,
            iundefsym,
            nundefsym,
            tocoff,
            ntoc,
            modtaboff,
            nmodtab,
            extrefsymoff,
            nextrefsyms,
            indirectsymoff,
            nindirectsyms,
            extreloff,
            nextrel,
            locreloff,
            nlocrel,
        }))
    )
}

pub fn parse_twolevel_hints_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_prebind_cksum_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_uuid_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        uuid: count_fixed!(u8, le_u8, 16) >>
        (LoadCommand::UuidCommand(uuid_command{cmd, cmdsize, uuid}))
    )
}

pub fn parse_rpath_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_linkedit_data_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        dataoff: le_u32 >>
        datasize: le_u32 >>
        (LoadCommand::LinkeditDataCommand(linkedit_data_command{cmd, cmdsize, dataoff, datasize}))
    )
}

pub fn parse_encryption_info_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_encryption_info_command_64(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_version_min_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        version: le_u32 >>
        sdk: le_u32 >>
        (LoadCommand::VersionMinCommand(version_min_command{cmd, cmdsize, version, sdk}))
    )
}

pub fn parse_build_version_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_dyld_info_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        rebase_off: le_u32 >>
        rebase_size: le_u32 >>
        bind_off: le_u32 >>
        bind_size: le_u32 >>
        weak_bind_off: le_u32 >>
        weak_bind_size: le_u32 >>
        lazy_bind_off: le_u32 >>
        lazy_bind_size: le_u32 >>
        export_off: le_u32 >>
        export_size: le_u32 >>
        (
            LoadCommand::DyldInfoCommand(dyld_info_command {
                cmd,
                cmdsize,
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
            })
        )
    )
}

pub fn parse_linker_option_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_symseg_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_ident_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_fvmfile_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}

pub fn parse_entry_point_command(cmd: u32, cmdsize: u32, input: &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        entryoff: le_u64 >>
        stacksize: le_u64 >>
        (LoadCommand::EntryPointCommand(entry_point_command {cmd, cmdsize, entryoff, stacksize}))
    )
}

pub fn parse_source_version_command(cmd: u32, cmdsize: u32, input : &[u8]) -> IResult<&[u8], LoadCommand> {
    do_parse!(input,
        version: le_u64 >>
        (LoadCommand::SourceVersionCommand(source_version_command {cmd, cmdsize, version}))
    )
}

pub fn parse_note_command(input : &[u8]) -> IResult<&[u8], LoadCommand> {
    unimplemented!()
}


pub fn parse_command(input: &[u8]) -> IResult<&[u8], LoadCommand> {
    match le_u32(&input) {
        IResult::Done(i, cmd) => {
            match le_u32(&i) {
                IResult::Done(i, cmdsize) => {
                    match cmd {
                        LC_SEGMENT_64 => parse_segment_command_64(cmd, cmdsize, &i),
                        LC_DYLD_INFO_ONLY => parse_dyld_info_command(cmd, cmdsize, &i),
                        LC_SYMTAB => parse_symtab_command(cmd, cmdsize, &i),
                        LC_DYSYMTAB => parse_dysymtab_command(cmd, cmdsize, &i),
                        LC_UUID => parse_uuid_command(cmd, cmdsize, &i),
                        LC_VERSION_MIN_MACOSX => parse_version_min_command(cmd, cmdsize, &i),
                        LC_SOURCE_VERSION => parse_source_version_command(cmd, cmdsize, &i),
                        LC_MAIN => parse_entry_point_command(cmd, cmdsize, &i),
                        LC_LOAD_DYLIB => parse_dylib_command(cmd, cmdsize, &i),
                        LC_FUNCTION_STARTS => parse_linkedit_data_command(cmd, cmdsize, &i),
                        LC_DATA_IN_CODE => parse_linkedit_data_command(cmd, cmdsize, &i),
                        x => panic!(format!("unknown {}", x)),
                    }
                },
                _ => panic!("unexpected"),
            }
        },
        _ => panic!("unexpected"),
    }
}

fn main() {
    let path = "target/debug/osect";
    let mut file = File::open(path).unwrap();
    let mut vec = vec![];
    let _ = file.read_to_end(&mut vec);
    let header = header(&vec).unwrap();
    println!("{:?}", header.1);
    let mut rest = header.0;
    loop {
        let command = match parse_command(&rest) {
            IResult::Done(i, o) => {
                rest = i;
                println!("{}", o);
            }
            _ => {}
        };
    }
}

#[cfg]
mod test {
    static INPUT:[u8;32] = [0xcfu8,0xfa,0xed,0xfe,0x07,0x00,0x00,0x01,0x03,0x00,0x00,0x80,0x02,0x00,0x00,0x00,0x1a,0x00,0x00,0x00,0x90,0x0b,0x00,0x00,0x85,0x00,0x20,0x00,0x00,0x00,0x00,0x00];
    #[test]
    fn test_parse_segment_command() {
        
    }
}
