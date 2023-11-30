use goblin::{error, Object};
use map_extract::{extract_gnu_mapfile, map_sections_to_elf};
use regex::RegexBuilder;

fn main() {
    let binary = std::fs::read("tests/a.out").unwrap();
    let object = Object::parse(&binary).expect("Open test1");
    if let Object::Elf(elf) = object {
        let shdrs = &elf.section_headers;
        let strtab = &elf.shdr_strtab;

        for shdr in shdrs {
            let section_name = strtab.get_at(shdr.sh_name).unwrap();
            println!(
                "Section {} @ {:x} (virt: {:x}), sz: {}",
                section_name, shdr.sh_offset, shdr.sh_addr, shdr.sh_size
            );
        }

        let map = std::fs::read_to_string("tests/out.map").unwrap();
        let mut map_info = extract_gnu_mapfile(&map);
        map_sections_to_elf(&mut map_info, &elf);
        println!("{:?}", map_info);
    }
}
