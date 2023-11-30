use elf::endian::AnyEndian;
use elf::note::Note;
use elf::note::NoteGnuBuildId;
use elf::section::SectionHeader;
use elf::ElfBytes;
use map_extract::extract_gnu_mapfile;
use regex::RegexBuilder;

fn main() {
    let binary = std::fs::read("tests/a.out").unwrap();
    let file = ElfBytes::<AnyEndian>::minimal_parse(&binary).expect("Open test1");
    let (Some(shdrs), Some(strtab)) = file.section_headers_with_strtab().unwrap() else {
        panic!("Could not parse section headers");
    };
    let sections = shdrs
        .into_iter()
        .filter_map(|shdr| strtab.get(shdr.sh_name as usize).ok())
        .collect::<Vec<_>>();

    println!("{sections:?}");
    let map = std::fs::read_to_string("tests/out.map").unwrap();

    for info in extract_gnu_mapfile(&map) {
        if !info.filename.starts_with("/usr/lib") {
            let start = info.vrom as usize;
            let size = info.size as usize;
            println!("{}", info.section_name);
            println!("{start}, {size}");
            println!("{}", String::from_utf8_lossy(&binary[start..start + size]));
        }
    }
}
