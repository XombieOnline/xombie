use clap::{App, Arg, ArgMatches, SubCommand};

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::exit;

fn main() {
    let matches = App::new("xbeeprom")
        .version("0.1.0")
        .about("Tool for inspecting and manipulating xbox eeprom images")
            .subcommand(SubCommand::with_name("info")
                .about("Print information about given eeprom")
                .arg(Arg::with_name("INPUT")
                    .help("Set the filename of the eeprom to use")
                    .required(true)
                    .index(1)))
        .get_matches();

    match matches.subcommand() {
        ("info", Some(matches)) => info_subcommand(matches),
        _ => {
            match matches.subcommand_name() {
                Some(name) => eprintln!("Error: Unknown subcommand: \"{}\"", name),
                None => eprintln!("Error: No subcommand given"),
            }
            eprintln!("{}", matches.usage());
            exit(1);
        }
    }
}


fn info_subcommand<'a>(matches: &ArgMatches<'a>) {
    let input_filename = matches.value_of("INPUT").unwrap();

    let file = read_file_to_buffer(input_filename).unwrap();

    let eeprom = xbox_sys::eeprom::Eeprom::from_buf(&file).unwrap();

    println!("Serial Number: {}", eeprom.serial_number());
    println!("MAC Address:   {}", eeprom.mac_address());
    println!("Online Key:    {}", eeprom.online_key());
}

fn read_file_to_buffer<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut buf = vec![];
    let mut file = fs::File::open(path)?;
    file.read_to_end(&mut buf)?;

    Ok(buf)
}
