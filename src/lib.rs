use std::{collections::HashMap, error::Error, fmt::Display, ops::Range};

use goblin::{elf::Elf, pe::PE, Object};
use intervaltree::{Element, IntervalTree};
use regex::{Captures, Regex, RegexBuilder};

#[derive(Clone, Debug)]
pub enum GenealogyError {
    UnsupportedBinaryFormat,
    WrongMapfileFormat,
}

impl Display for GenealogyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenealogyError::UnsupportedBinaryFormat => {
                write!(
                    f,
                    "Binary format not supported. Only ELF and PE supported for now.",
                )
            }
            GenealogyError::WrongMapfileFormat => {
                write!(f, "Mapfile not conforming to the expected format")
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
        let mut sections = extract_mapfile(mapfile)?;

        match Object::parse(binary).map_err(|_| GenealogyError::UnsupportedBinaryFormat)? {
            Object::Elf(elf) => {
                map_sections_to_elf(&mut sections, &elf);
            }
            Object::PE(pe) => map_msvc_sections_to_pe(&mut sections, &pe),
            _ => {
                return Err(GenealogyError::UnsupportedBinaryFormat);
            }
        }

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

fn extract_mapfile(mapfile: &str) -> Result<Vec<Section>, GenealogyError> {
    let header_regex = Regex::new(
        r"VMA(?:\s+)LMA(?:\s+)Size(?:\s+)Align(?:\s+)Out(?<out_in_space>\s+)In(?:\s+)Symbol",
    )
    .expect("I know how to write regexes");

    if let Some(header_match) = header_regex.captures(mapfile) {
        Ok(extract_llvm_mapfile(
            mapfile,
            header_match["out_in_space"].len(),
        ))
    } else if mapfile.contains("Preferred load address is ") {
        extract_msvc_mapfile(mapfile)
    } else {
        Ok(extract_gnu_mapfile(mapfile))
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

fn extract_msvc_mapfile(mapfile: &str) -> Result<Vec<Section>, GenealogyError> {
    // We don't have the same information for msvc mapfiles as we havec for other kinds
    // However, msvc mapfiles will (should ?) only ever be associated with PE binaries.
    // The PE reader provides the size and file pointer for each section, while the mapfile
    // provides information about "subsections" relative to the start of the section.
    // Thus, we will not really use the names of the (sub-)sections, and instead refer to them by
    // index, and the virtual addresses are not absolute (too cumbersome) but relative to the
    // vaddr of the section start.
    // Furtermore, because msvc mapfiles do not really contain the same information as other
    // types of mapfiles (subsection with origin), we will have to "cheat" a little bit and instead
    // try to find subsection boundaries with origins by looking at the static symbol offsets and supposing
    // that in a contiguous section of symbols from the same origin, everything in between has also the same origin
    let line_regex =
        Regex::new(r"^ (?<section>[0-9a-zA-Z]{4}):(?<section_offset>[0-9a-zA-Z]{8})\s+(?<name>[^ ]+)\s+(?<vaddr>[0-9a-zA-Z]{16})(?: \w)?\s+(?<origin>.+)$").unwrap();

    // Find the offset of the static symbols section
    let offset = mapfile
        .find(" Static symbols")
        .ok_or(GenealogyError::WrongMapfileFormat)?;

    let mut lines = mapfile[offset..].lines();
    lines.next(); // skip " Static symbols" line
    lines.next(); // skip the following newline

    // Let's go
    let mut res = vec![];
    let mut current_filename = None;
    let mut current_start_offset = 0;
    let mut current_section_nb = 0;

    let mut prev_section_offset = 0;
    for line in lines {
        let Some(capture) = line_regex.captures(line) else {
            break;
        };
        let section_nb = u64::from_str_radix(&capture["section"], 16)
            .map_err(|_| GenealogyError::WrongMapfileFormat)?;
        let section_offset = u64::from_str_radix(&capture["section_offset"], 16)
            .map_err(|_| GenealogyError::WrongMapfileFormat)?;
        // let vaddr = u64::from_str_radix(&capture["vaddr"], 16)
        //    .map_err(|_| GenealogyError::WrongMapfileFormat)?;
        while res.len() <= section_nb as usize {
            res.push(Section {
                name: "".into(),
                start_vaddr: 0,
                start_file_offset: None,
                size: 0,
                subsections: vec![],
            });
        }
        let filename = capture["origin"]
            .split(':')
            .next()
            .expect("at least one element in split iterator")
            .to_string();
        if current_filename.is_none() {
            current_filename = Some(filename);
            current_start_offset = section_offset;
        } else if let Some(current_filename_value) = &current_filename {
            // Change current values and push subsection if needed
            if current_filename_value != &filename || current_section_nb != section_nb {
                res[current_section_nb as usize]
                    .subsections
                    .push(SubSection {
                        name: String::new(),
                        start_vaddr: current_start_offset, // /!\ not actually the vaddr but it's easier to do so
                        start_file_offset: None,
                        size: prev_section_offset - current_start_offset + 1, // an underestimation but what can we do ?
                        filename: current_filename_value.clone(),
                    });
                current_filename = Some(filename);
                current_start_offset = section_offset;
                current_section_nb = section_nb;
            }
        }

        prev_section_offset = section_offset;
    }

    // The last one
    if let Some(filename) = current_filename {
        res[current_section_nb as usize]
            .subsections
            .push(SubSection {
                name: String::new(),
                start_vaddr: current_start_offset, // /!\ not actually the vaddr but it's easier to do so
                start_file_offset: None,
                size: prev_section_offset - current_start_offset + 1, // an underestimation but what can we do ?
                filename,
            });
    }

    Ok(res)
}

fn map_msvc_sections_to_pe(sections: &mut [Section], pe: &PE) {
    for (section_nb, section) in sections.iter_mut().enumerate() {
        if section_nb == 0 {
            continue;
        }
        let Some(pe_section) = pe.sections.get(section_nb - 1) else {
            // No info about this section :(
            continue;
        };
        let pointer_offset = pe_section.pointer_to_raw_data;

        for subsection in &mut section.subsections {
            subsection.start_file_offset = Some(pointer_offset as u64 + subsection.start_vaddr);
        }
    }
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
        let mut sections = extract_mapfile(&file).unwrap();

        let binary = std::fs::read("tests/clang/a.out").unwrap();
        let object = Object::parse(&binary).expect("Open test1");
        if let Object::Elf(elf) = object {
            map_sections_to_elf(&mut sections, &elf)
        }
    }
}
