use nom::number::complete::{le_i64, le_u16, le_u32, le_u64, le_i32};
use crate::timespec;

pub const TS_GLOBAL: u16 = 1;
pub const TS_TTY: u16 = 2;
pub const TS_PPID: u16 = 3;
pub const TS_LOCKEXCL: u16 = 4;

pub const TS_DISABLED: u16 = 0x01;
pub const TS_ANYUID: u16 = 0x02;


pub fn parse_ts_file(
    raw: &[u8],
) -> Result<Vec<TimestampEntry>, nom::Err<nom::error::Error<&[u8]>>> {
    let mut local_raw = raw;
    let mut tses = Vec::new();

    loop {
        let (iter_raw, tse) = parse_ts_entry(local_raw)?;
        local_raw = iter_raw;
        tses.push(tse);
        if local_raw.is_empty() {
            break;
        }
    }

    return Ok(tses);
}

fn parse_ts_entry(
    raw: &[u8],
) -> Result<(&[u8], TimestampEntry), nom::Err<nom::error::Error<&[u8]>>> {
    let (raw, version) = le_u16(raw)?;
    let (raw, size) = le_u16(raw)?;
    let (raw, type_) = le_u16(raw)?;
    let (raw, flags) = le_u16(raw)?;
    let (raw, auth_uid) = le_u32(raw)?;
    let (raw, sid) = le_i32(raw)?;

    // In Version 1, the start_time was not included:
    // https://github.com/sudo-project/sudo/commit/1709dc7f77
    let (raw, start_time) = if version > 1 {
        parse_ts_timespec(raw)?
    } else {
        (
            raw,
            timespec::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        )
    };
    let (raw, ts) = parse_ts_timespec(raw)?;
    let (raw, id) = le_u64(raw)?;

    return Ok((
        raw,
        TimestampEntry {
            version,
            size,
            type_,
            flags,
            auth_uid,
            sid,
            start_time,
            ts,
            id,
        },
    ));
}

fn parse_ts_timespec(
    raw: &[u8],
) -> Result<(&[u8], timespec::timespec), nom::Err<nom::error::Error<&[u8]>>> {
    let (raw, tv_sec) = le_i64(raw)?;
    let (raw, tv_nsec) = le_i64(raw)?;

    return Ok((raw, timespec::timespec { tv_sec, tv_nsec }));
}

#[derive(Debug)]
pub struct TimestampEntry {
    pub version: u16,
    pub size: u16,
    pub type_: u16,
    pub flags: u16,
    pub auth_uid: u32,
    pub sid: i32,
    pub start_time: timespec::timespec,
    pub ts: timespec::timespec,

    // ttydev or ppid
    pub id: u64,
}

impl TimestampEntry {
    pub fn new_lockexcl() -> Self {
        Self {
            version: 2,
            size: 56,
            type_: TS_LOCKEXCL,
            flags: 0,
            auth_uid: 0,
            sid: 0,
            start_time: timespec::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            ts: timespec::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            id: 0,
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend(&self.version.to_le_bytes());
        raw.extend(&self.size.to_le_bytes());
        raw.extend(&self.type_.to_le_bytes());
        raw.extend(&self.flags.to_le_bytes());
        raw.extend(&self.auth_uid.to_le_bytes());
        raw.extend(&self.sid.to_le_bytes());
        if self.version != 1 {
            raw.extend(&timespec_build(self.start_time));
        }
        raw.extend(&timespec_build(self.ts));
        raw.extend(&self.id.to_le_bytes());

        return raw;
    }
}



fn timespec_build(ts: timespec::timespec) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend(&ts.tv_sec.to_le_bytes());
    raw.extend(&ts.tv_nsec.to_le_bytes());
    return raw;
}
