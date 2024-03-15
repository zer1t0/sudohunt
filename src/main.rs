mod cmd_inject;
mod cmd_read;
mod cmd_write;
mod proc;
mod sudo;
mod timespec;
mod timestamp;
mod traceter;
mod utils;

use clap::{Parser, Subcommand};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use std::str;

/// Inspect sudo login timestamps
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    verbose: Verbosity<WarnLevel>,
}

#[derive(Subcommand)]
enum Commands {
    /// Read the sudo timestamp files
    Read(cmd_read::ReadArgs),

    /// Write a record in sudo timestamp files
    Write(cmd_write::WriteArgs),

    /// Inject into user sessions
    Inject(cmd_inject::InjectArgs),
}

fn main() {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    if let Err(err) = match cli.command {
        Commands::Read(args) => cmd_read::main_read(args),
        Commands::Write(args) => cmd_write::main_write(args),
        Commands::Inject(args) => cmd_inject::main_inject(args),
    } {
        log::error!("{}", err);
        std::process::exit(-1);
    }

    std::process::exit(0);
}
