use crate::timespec;
use crate::utils;
use libc::{self, _SC_CLK_TCK};
use std::fs;
use std::str;

pub fn process_ruid(pid: i32) -> Result<u32, String> {
    let filepath = format!("/proc/{}/status", pid);

    for line in fs::read_to_string(&filepath)
        .map_err(|e| format!("Unable to read {}: {}", filepath, e))?
        .lines()
    {
        if !line.starts_with("Uid:") {
            continue;
        }

        let ruid_str = line.split("\t").skip(1).next().unwrap();
        let ruid: u32 = ruid_str.parse().unwrap();
        return Ok(ruid);
    }

    return Err(format!("Unable to find real uid for process {}", pid));
}

pub fn process_tty_dev_t(pid: i32) -> Result<u64, String> {
    let filepath = format!("/proc/{}/stat", pid);

    let text = fs::read_to_string(&filepath)
        .map_err(|e| format!("Unable to read {}: {}", filepath, e))?;

    let parts: Vec<&str> = text.split(")").last().unwrap().split(" ").collect();

    let tty_str = parts
        .get(5)
        .ok_or_else(|| format!("Proccess {} tty number not found", pid))?;

    let tty_dev: u64 = tty_str
        .parse()
        .map_err(|_| format!("Unable to parse process {} tty number", pid))?;

    return Ok(tty_dev);
}

pub fn process_start_time(pid: i32) -> Result<timespec::timespec, String> {
    let tps = unsafe { libc::sysconf(_SC_CLK_TCK) };
    if tps < 1 {
        return Err(format!("Unable to get ticks per second configuration"));
    }

    log::debug!("Ticks per second: {}", tps);

    let filepath = format!("/proc/{}/stat", pid);

    let text = fs::read_to_string(&filepath)
        .map_err(|e| format!("Unable to read {}: {}", filepath, e))?;

    let parts: Vec<&str> = text.split(")").last().unwrap().split(" ").collect();

    let start_time_str = parts
        .get(20)
        .ok_or_else(|| format!("Proccess {} start time not found", pid))?;

    let start_time_ticks: i64 = start_time_str
        .parse()
        .map_err(|_| format!("Unable to parse process {} start time", pid))?;

    log::debug!("Process {} start time: {}", pid, start_time_ticks);
    let secs = start_time_ticks / tps;
    let nsecs = (start_time_ticks % tps) * (1000000000 / tps);

    return Ok(timespec::timespec {
        tv_sec: secs,
        tv_nsec: nsecs,
    });
}

pub fn process_cmdline(pid: i32) -> Result<String, String> {
    let filepath = format!("/proc/{}/cmdline", pid);
    let bytes = utils::read_file_bytes(filepath)?;

    let mut cmdline_args = Vec::new();
    let mut accum_bytes = Vec::new();
    for b in bytes.iter() {
        if *b != 0 {
            accum_bytes.push(*b);
            continue;
        }

        let s = str::from_utf8(&accum_bytes).unwrap().to_string();
        cmdline_args.push(s);
        accum_bytes.clear();
    }

    return Ok(cmdline_args.join(" ").into());
}
