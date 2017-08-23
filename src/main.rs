
extern crate getopts;
extern crate mpq;

use mpq::Archive;
use std::env;
use std::process;
use std::str;

fn print_usage(program: &str, opts: &getopts::Options) {
    let brief = format!("Usage: {} [options] MPQ_FILE", program);
    print!("{}", opts.usage(&brief));
}

fn list(archive_file_name: &str) {
    let mut archive = match Archive::open(archive_file_name) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", e);
            process::exit(1);
        }
    };

    let file = match archive.open_file("(listfile)") {
        Ok(v) => v,
        Err(e) => {
            println!("{}", e);
            process::exit(1);
        }
    };

    let mut buf: Vec<u8> = vec![0; file.size() as usize];

    match file.read(&mut archive, &mut buf) {
        Ok(_) => {},
        Err(e) => {
            println!("{}", e);
            process::exit(1);
        }
    }

    print!("{}", str::from_utf8(&buf).unwrap());
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();
    let mut opts = getopts::Options::new();

    opts.optopt("x", "extract", "extract file from archive", "FILE");
    opts.optflag("l", "list", "print (listfile) contents");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string())
    };

    if matches.opt_present("help") {
        print_usage(&program, &opts);
        return;
    }

    let archive_file_name = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, &opts);
        return;
    };

    if matches.opt_present("list") {
        list(&archive_file_name.clone());
        return;
    }

    if let Some(filename) = matches.opt_str("extract") {
        let mut archive = match Archive::open(archive_file_name) {
            Ok(v) => v,
            Err(e) => {
                println!("{}", e);
                process::exit(1);
            }
        };

        let file = archive.open_file(&filename).unwrap();

        match file.extract(&mut archive, &filename) {
            Ok(_) => {},
            Err(e) => {
                println!("{}", e);
                process::exit(1);
            }
        }
    }
}
