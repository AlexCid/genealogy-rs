use genealogy::Genealogy;

fn main() {
    let binary_path = "tests/cargo/genealogy";
    let map_path = "tests/cargo/out.map";

    let binary = std::fs::read(binary_path).unwrap();
    let mapfile = std::fs::read_to_string(map_path).unwrap();

    let gen = Genealogy::new(&mapfile, &binary).unwrap();
    println!("Files were parsed");
    println!("{:?}", gen.query_point(0x1df793).collect::<Vec<_>>());
}
