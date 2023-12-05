use std::{collections::HashMap, error::Error, fmt::Display, ops::Range};

use goblin::{elf::Elf, Object};
use intervaltree::{Element, IntervalTree};
use regex::{Captures, Regex, RegexBuilder};

#[derive(Clone, Debug)]
pub enum GenealogyError {
    UnsupportedBinaryFormat,
}

impl Display for GenealogyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenealogyError::UnsupportedBinaryFormat => {
                write!(
                    f,
                    "Binary format not supported. Only ELF supported for now.",
                )
            }
        }
    }
}

impl Error for GenealogyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}

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

pub struct Genealogy {
    intervals: IntervalTree<u64, String>,
}

impl Genealogy {
    pub fn new(mapfile: &str, binary: &[u8]) -> Result<Self, GenealogyError> {
        let mut sections = extract_mapfile(mapfile);
        let Object::Elf(elf) =
            Object::parse(binary).map_err(|_| GenealogyError::UnsupportedBinaryFormat)?
        else {
            return Err(GenealogyError::UnsupportedBinaryFormat);
        };
        map_sections_to_elf(&mut sections, &elf);

        // Build interval tree
        let intervals: IntervalTree<u64, String> = IntervalTree::from_iter(
            sections
                .into_iter()
                .flat_map(|s| s.subsections.into_iter())
                .filter_map(|sub_section| {
                    sub_section.start_file_offset.map(|file_offset| {
                        (
                            file_offset..file_offset + sub_section.size,
                            sub_section.filename,
                        )
                    })
                }),
        );

        Ok(Self { intervals })
    }

    pub fn query(&self, range: Range<u64>) -> impl Iterator<Item = &Element<u64, String>> {
        self.intervals.query(range)
    }

    pub fn query_point(&self, point: u64) -> impl Iterator<Item = &Element<u64, String>> {
        self.intervals.query_point(point)
    }
}

fn extract_mapfile(mapfile: &str) -> Vec<Section> {
    let header_regex = Regex::new(
        r"VMA(?:\s+)LMA(?:\s+)Size(?:\s+)Align(?:\s+)Out(?<out_in_space>\s+)In(?:\s+)Symbol",
    )
    .expect("I know how to write regexes");

    if let Some(header_match) = header_regex.captures(mapfile) {
        extract_llvm_mapfile(mapfile, header_match["out_in_space"].len())
    } else {
        extract_gnu_mapfile(mapfile)
    }
}

fn extract_gnu_mapfile(mapfile: &str) -> Vec<Section> {
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

fn extract_llvm_mapfile(mapfile: &str, out_in_len: usize) -> Vec<Section> {
    enum EntryType {
        Section(Section),
        SubSection(SubSection),
    }
    fn capture_to_entry_type(m: Captures<'_>, out_in_space: usize) -> Option<EntryType> {
        let start_vaddr = u64::from_str_radix(&m["vma"], 16).unwrap();
        let size = u64::from_str_radix(&m["size"], 16).unwrap();
        if m["spaces"].len() == 1 {
            // Section header
            Some(EntryType::Section(Section {
                name: m["name"].to_string(),
                start_vaddr,
                start_file_offset: None,
                size,
                subsections: vec![],
            }))
        } else if m["spaces"].len() == 1 + 3 + out_in_space {
            // A subsection
            let (filename, mut name) = m["name"][..m["name"].len() - 1].split_once(":(").unwrap();
            // Remove a potential +0xXXX substring for the subsection name, where XXX are hex digits
            if let Some(plus_pos) = name.rfind("+0x") {
                if name[plus_pos + 3..]
                    .chars()
                    .all(|c| matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F'))
                {
                    // If it is indeed a +0xXXX suffix indicating the offset which we ignore
                    name = &name[..plus_pos];
                }
            }
            Some(EntryType::SubSection(SubSection {
                name: name.to_string(),
                start_vaddr,
                start_file_offset: None,
                size,
                filename: filename.to_string(),
            }))
        } else {
            // A symbol, ignore for now
            None
        }
    }

    let line_regex = Regex::new(
        r"^(?:\s)*(?<vma>[0-9a-fA-F]+)(?:\s)*(?<lma>[0-9a-fA-F]+)(?:\s)*(?<size>[0-9a-fA-F]+)(?:\s)*(?<align>[0-9]+)(?<spaces>\s+)(?<name>.+)$",
    ).unwrap();

    let mut lines = mapfile.lines();
    lines.next(); // skip header, handled by regex

    let mut res = vec![];

    let Some(next_line) = lines.next() else {
        return res;
    };
    let Some(regex_capture) = line_regex.captures(next_line) else {
        return res;
    };
    let Some(EntryType::Section(mut cur_section)) =
        capture_to_entry_type(regex_capture, out_in_len)
    else {
        return res;
    };

    for line in lines {
        let Some(capture) = line_regex.captures(line) else {
            continue;
        };
        match capture_to_entry_type(capture, out_in_len) {
            Some(EntryType::Section(section)) => {
                res.push(cur_section);
                cur_section = section;
            }
            Some(EntryType::SubSection(subsection)) => {
                cur_section.subsections.push(subsection);
            }
            None => {
                continue;
            }
        }
    }

    res.push(cur_section);

    res
}

fn map_sections_to_elf(sections: &mut [Section], elf: &Elf) {
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

#[cfg(test)]
mod tests {
    use goblin::Object;

    use crate::{extract_mapfile, map_sections_to_elf};

    #[test]
    fn test_llvm_mapfile() {
        let file = std::fs::read_to_string("tests/clang/output.map").unwrap();
        let mut sections = extract_mapfile(&file);

        let binary = std::fs::read("tests/clang/a.out").unwrap();
        let object = Object::parse(&binary).expect("Open test1");
        if let Object::Elf(elf) = object {
            map_sections_to_elf(&mut sections, &elf)
        }
        println!("{:#?}", sections);
    }
}
