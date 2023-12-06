use genealogy::Genealogy;

fn main() {
    let binary_path = "tests/cargo-windows/genealogy.exe";
    let map_path = "tests/cargo-windows/out.map";

    let binary = std::fs::read(binary_path).unwrap();
    let mapfile = std::fs::read_to_string(map_path).unwrap();

    let genealogy = Genealogy::new(&mapfile, &binary).unwrap();
    println!("{:?}", genealogy.query_point(0x135900).collect::<Vec<_>>());
}
