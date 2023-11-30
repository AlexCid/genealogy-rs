use regex::RegexBuilder;

pub struct MapfileInformation {
    pub section_name: String,
    pub vrom: u64,
    pub size: u64,
    pub filename: String,
}

pub fn extract_gnu_mapfile(mapfile: &str) -> Vec<MapfileInformation> {
    let regex = RegexBuilder::new(r"^ (?P<name>\.[^\s]+)\s+0x(?P<vrom>[0-9a-fA-F]+)[[:blank:]]+0x(?P<size>[0-9a-fA-F]+)[[:blank:]]+(?P<file>[^\r\n]+)")
    .multi_line(true)
    .build()
    .unwrap();

    regex
        .captures_iter(mapfile)
        .map(|c| MapfileInformation {
            section_name: c["name"].to_string(),
            vrom: u64::from_str_radix(&c["vrom"], 16).unwrap(),
            size: u64::from_str_radix(&c["size"], 16).unwrap(),
            filename: c["file"].to_string(),
        })
        .collect()
}
