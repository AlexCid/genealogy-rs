use std::collections::HashMap;

use goblin::elf::Elf;
use regex::RegexBuilder;

#[derive(Debug)]
pub struct MapfileInformation {
    pub section_name: String,
    pub vrom: u64,
    pub size: u64,
    pub filename: String,
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub start_vaddr: u64,
    pub start_file_offset: Option<u64>,
    pub size: u64,
    pub subsections: Vec<SubSection>,
}
#[derive(Debug)]
pub struct SubSection {
    pub name: String,
    pub start_vaddr: u64,
    pub start_file_offset: Option<u64>,
    pub size: u64,
    pub filename: String,
}

pub fn extract_gnu_mapfile(mapfile: &str) -> Vec<Section> {
    let regex_subsections = RegexBuilder::new(r"^ (?P<name>\.[^\s]+)\s+0x(?P<vrom>[0-9a-fA-F]+)[[:blank:]]+0x(?P<size>[0-9a-fA-F]+)[[:blank:]]+(?P<file>[^\r\n]+)")
    .multi_line(true)
    .build()
    .unwrap();

    let regex_sections = RegexBuilder::new(
        r"^(?P<name>\.[^\s]+)\s+0x(?P<vrom>[0-9a-fA-F]+)[[:blank:]]+0x(?P<size>[0-9a-fA-F]+)",
    )
    .multi_line(true)
    .build()
    .unwrap();

    // Extract all sections, don't fill subsections in yet
    let (section_offsets, mut sections): (Vec<usize>, Vec<Section>) = regex_sections
        .captures_iter(mapfile)
        .map(|c| {
            (
                c.get(0).unwrap().start(),
                Section {
                    name: c["name"].into(),
                    start_vaddr: u64::from_str_radix(&c["vrom"], 16).unwrap(),
                    size: u64::from_str_radix(&c["size"], 16).unwrap(),
                    subsections: vec![],
                    start_file_offset: None,
                },
            )
        })
        .unzip();

    // Assign each subsection to the closest section
    regex_subsections.captures_iter(mapfile).for_each(|c| {
        let subsection = SubSection {
            name: c["name"].to_string(),
            start_vaddr: u64::from_str_radix(&c["vrom"], 16).unwrap(),
            size: u64::from_str_radix(&c["size"], 16).unwrap(),
            filename: c["file"].to_string(),
            start_file_offset: None,
        };
        let ss_offset = c.get(0).unwrap().start();
        // Find closest section
        let section_index = section_offsets
            .iter()
            .enumerate()
            .find_map(|(i, &s_offset)| Some(i).filter(|_| s_offset > ss_offset))
            .unwrap_or(sections.len());
        if section_index > 0 {
            sections[section_index - 1].subsections.push(subsection);
        }
    });

    sections
}

pub fn map_sections_to_elf(sections: &mut [Section], elf: &Elf) {
    /*
        For each section:
        - Find the named section in the Elf file
        - Find the file offset and fill it in
        - Do the same for all subsections
    */

    // Maps a section header name to its offset in the file
    let elf_section_hm: HashMap<&str, _> = elf
        .section_headers
        .iter()
        .map(|shdr| {
            (
                elf.shdr_strtab.get_at(shdr.sh_name).unwrap(),
                shdr.sh_offset,
            )
        })
        .collect();

    sections.iter_mut().for_each(|section| {
        section.start_file_offset = elf_section_hm.get(section.name.as_str()).copied();
        if let Some(file_offset) = section.start_file_offset {
            section.subsections.iter_mut().for_each(|ssection| {
                ssection.start_file_offset =
                    Some(ssection.start_vaddr - section.start_vaddr + file_offset);
            });
        }
    })
}
