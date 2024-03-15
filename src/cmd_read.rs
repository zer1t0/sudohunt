use crate::timestamp::{
    TimestampEntry, TS_ANYUID, TS_DISABLED, TS_GLOBAL, TS_LOCKEXCL, TS_PPID,
    TS_TTY,
};
use clap::Args;
use std::fs;
use std::str;
use crate::timespec;
use crate::utils;
use crate::timestamp;
use crate::proc;

#[derive(Args)]
pub struct ReadArgs {
    /// Path to read sudo timestamps. If directory is specified all files will be read
    #[arg(short, long, default_value_t = format!("/run/sudo/ts"))]
    path: String,
}

pub fn main_read(args: ReadArgs) -> Result<(), String> {
    let ts_path = args.path;

    let ts_now = timespec::timespec_now()?;

    let paths = if fs::metadata(&ts_path)
        .map_err(|e| format!("Unable to check {} metadata: {}", ts_path, e))?
        .is_dir()
    {
        fs::read_dir(&ts_path)
            .map_err(|e| format!("Unable to open {}: {}", ts_path, e))?
            .map(|p| {
                p.unwrap().path().as_os_str().to_str().unwrap().to_string()
            })
            .collect()
    } else {
        vec![ts_path]
    };

    for path in paths {
        println!("\n\nTimestamp file: {}", path);
        let buffer = utils::read_file_bytes(&path)?;

        match timestamp::parse_ts_file(buffer.as_slice()) {
            Ok(tses) => {
                for tse in tses {
                    println!("");
                    print_timestamp_entry(&tse, ts_now);
                }
            }
            Err(err) => {
                log::warn!("Error parsing timestamps: {}", err)
            }
        }
    }

    return Ok(());
}

fn print_timestamp_entry(tse: &TimestampEntry, ts_now: timespec::timespec) {
    println!("version: {}", tse.version);
    println!("size: {}", tse.size);
    let type_str = match tse.type_ {
        TS_GLOBAL => "TS_GLOBAL",
        TS_TTY => "TS_TTY",
        TS_PPID => "TS_PPID",
        TS_LOCKEXCL => "TS_LOCKEXCL",
        _ => "UNKNOWN",
    };
    println!("type: {} {}", tse.type_, type_str);

    let mut flags_str = Vec::new();
    if (tse.flags & TS_DISABLED) != 0 {
        flags_str.push("TS_DISABLED");
    }
    if (tse.flags & TS_ANYUID) != 0 {
        flags_str.push("TS_ANYUID");
    }
    println!("flags: {} {}", tse.flags, flags_str.join(", "));

    let username = if tse.type_ == TS_LOCKEXCL {
        "".to_string()
    } else {
        utils::uid_to_username(tse.auth_uid).unwrap_or("".into())
    };
    println!("auth_uid: {} {}", tse.auth_uid, username);

    let cmdline = if tse.sid != 0 {
        proc::process_cmdline(tse.sid).unwrap_or("".into())
    } else {
        "".into()
    };

    println!("sid: {} {}", tse.sid, cmdline);
    if tse.version != 1 {
        if tse.type_ != TS_LOCKEXCL {
            let diff = timespec::timespec_sub(ts_now, tse.start_time);

            println!(
                "start_time: {}.{} ({}.{} seconds ago)",
                tse.start_time.tv_sec,
                tse.start_time.tv_nsec,
                diff.tv_sec,
                diff.tv_nsec
            );
        } else {
            println!(
                "start_time: {}.{}",
                tse.start_time.tv_sec, tse.start_time.tv_nsec
            );
        }
    }

    if tse.type_ != TS_LOCKEXCL {
        let diff = timespec::timespec_sub(ts_now, tse.ts);
        println!(
            "ts: {}.{} ({}.{} seconds ago)",
            tse.ts.tv_sec, tse.ts.tv_nsec, diff.tv_sec, diff.tv_nsec
        );
    } else {
        println!("ts: {}.{}", tse.ts.tv_sec, tse.ts.tv_nsec);
    }

    match tse.type_ {
        TS_TTY => {
            let name = utils::dev_t_to_name(tse.id).unwrap_or("".to_string());
            println!("tty: {} {}", tse.id, name);
        }
        TS_PPID => {
            let cmdline = proc::process_cmdline(tse.sid).unwrap_or("".into());
            println!("ppid: {} {}", tse.id, cmdline);
        }
        _ => println!("id: {}", tse.id),
    }
}
