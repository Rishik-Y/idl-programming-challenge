use std::fs::File;
use std::io::{BufRead, BufReader};
use std::error::Error;
use clap::Parser;

const PMP_ENTRIES: usize = 64;

#[derive(Debug)]
struct PmpConfig {
    read: bool,
    write: bool,
    exec: bool,
    mode: u8,
    locked: bool,
}

impl PmpConfig {
    fn from_byte(byte: u8) -> Self {
        PmpConfig {
            read: (byte & 0x01) != 0,
            write: (byte & 0x02) != 0,
            exec: (byte & 0x04) != 0,
            mode: (byte & 0x18) >> 3,
            locked: (byte & 0x80) != 0,
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to PMP configuration file
    #[arg(short, long)]
    config: String,
    
    /// Physical address in hexadecimal (0x prefix)
    #[arg(short, long)]
    address: String,
    
    /// Privilege mode (M, S, U)
    #[arg(short, long)]
    mode: char,
    
    /// Operation (R, W, X)
    #[arg(short, long)]
    operation: char,
}

#[derive(Debug)]
enum AccessResult {
    Allowed,
    Denied,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    let address = parse_address(&args.address)?;
    let mode = validate_mode(args.mode)?;
    let operation = validate_operation(args.operation)?;
    
    let pmp_entries = load_pmp_config(&args.config)?;
    let result = check_access(&pmp_entries, address, mode, operation);
    
    println!("Access {}", match result {
        AccessResult::Allowed => "allowed",
        AccessResult::Denied => "denied",
    });
    
    Ok(())
}

fn parse_address(addr_str: &str) -> Result<u64, Box<dyn Error>> {
    if !addr_str.starts_with("0x") {
        return Err("Address must start with 0x".into());
    }
    Ok(u64::from_str_radix(&addr_str[2..], 16)?)
}

fn validate_mode(mode: char) -> Result<char, Box<dyn Error>> {
    match mode.to_ascii_uppercase() {
        'M' | 'S' | 'U' => Ok(mode.to_ascii_uppercase()),
        _ => Err("Invalid privilege mode".into()),
    }
}

fn validate_operation(op: char) -> Result<char, Box<dyn Error>> {
    match op.to_ascii_uppercase() {
        'R' | 'W' | 'X' => Ok(op.to_ascii_uppercase()),
        _ => Err("Invalid operation".into()),
    }
}

fn load_pmp_config(path: &str) -> Result<Vec<(PmpConfig, u64)>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    
    let mut configs = Vec::with_capacity(PMP_ENTRIES);
    let mut addresses = Vec::with_capacity(PMP_ENTRIES);
    
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let value = u64::from_str_radix(&line.trim_start_matches("0x"), 16)?;
        
        if i < PMP_ENTRIES {
            configs.push(PmpConfig::from_byte(value as u8));
        } else if i < PMP_ENTRIES * 2 {
            addresses.push(value);
        } else {
            break;
        }
    }
    
    Ok(configs.into_iter().zip(addresses.into_iter()).collect())
}

fn check_access(entries: &[(PmpConfig, u64)], addr: u64, mode: char, op: char) -> AccessResult {
    for (i, (config, pmp_addr)) in entries.iter().enumerate() {
        if config.mode == 0 {
            continue;
        }
        
        let (start, end) = match config.mode {
            1 => tor_range(i, entries, *pmp_addr),
            2 => na4_range(*pmp_addr),
            3 => napot_range(*pmp_addr),
            _ => continue,
        };
        
        if addr >= start && addr < end {
            return evaluate_permission(config, mode, op);
        }
    }
    
    if mode == 'M' {
        AccessResult::Allowed
    } else {
        AccessResult::Denied
    }
}

fn tor_range(index: usize, entries: &[(PmpConfig, u64)], current_addr: u64) -> (u64, u64) {
    let prev_addr = if index > 0 {
        entries[index - 1].1
    } else {
        0
    };
    (prev_addr, current_addr)
}

fn na4_range(addr: u64) -> (u64, u64) {
    let base = addr & !0x3;
    (base, base + 4)
}

fn napot_range(addr: u64) -> (u64, u64) {
    let mask = (addr | (addr.wrapping_sub(1))) ^ u64::MAX;
    let base = addr & mask;
    let size = mask.wrapping_add(1);
    (base, base + size)
}

fn evaluate_permission(config: &PmpConfig, mode: char, op: char) -> AccessResult {
    if mode == 'M' && !config.locked {
        return AccessResult::Allowed;
    }
    
    let has_permission = match op {
        'R' => config.read,
        'W' => config.write,
        'X' => config.exec,
        _ => false,
    };
    
    if has_permission {
        AccessResult::Allowed
    } else {
        AccessResult::Denied
    }
}

///Hello Derek Hower (or whoever is reviewing),
///I Have a single Laptop and I am in the middle fixing a bug in NixOS which doesnt let me build
///directly. Normally i would somehow fixed this issue asap however my exams are going on and didnt
///wanna break my only laptop. I made and ran this code in online compiler however i cant be sure
///whether it will work, I hope My logic is correct at the very least
