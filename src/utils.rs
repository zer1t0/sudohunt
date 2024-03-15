use std::io::{self, Read};
use std::{
    env,
    fs::{self, File},
    path::Path,
};


pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn getmysid() -> i32 {
    return getsid(0).unwrap();
}

pub fn getsid(pid: i32) -> Option<i32> {
    let sid = unsafe { libc::getsid(pid) };
    if sid == -1 {
        return None;
    }
    return Some(sid);
}

pub fn getppid() -> i32 {
    unsafe { libc::getppid() }
}


pub fn read_file_bytes<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, String> {
    let mut f = File::open(&path).map_err(|e| {
        format!("Unable to open {}: {}", path.as_ref().to_str().unwrap(), e)
    })?;

    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).map_err(|e| {
        format!("Unable to read {}: {}", path.as_ref().to_str().unwrap(), e)
    })?;

    return Ok(buffer);
}

pub fn username_to_uid(username: &str) -> Result<u32, String> {
    for entry in parse_etc_passwd()
        .map_err(|e| format!("Unable to read /etc/passwd: {}", e))?
    {
        if username == entry.name {
            return Ok(entry.uid);
        }
    }

    return Err(format!("Unable to found uid for user {}", username));
}

pub fn uid_to_username(uid: u32) -> Result<String, String> {
    for entry in parse_etc_passwd()
        .map_err(|e| format!("Unable to read /etc/passwd: {}", e))?
    {
        if uid == entry.uid {
            return Ok(entry.name);
        }
    }

    return Err(format!("Unable to found user for uid {}", uid));
}

pub struct PasswordEntry {
    pub name: String,
    pub enc_password: String,
    pub uid: u32,
    pub gid: u32,
    pub comment: String,
    pub home: String,
    pub command: String,
}

fn parse_etc_passwd() -> Result<Vec<PasswordEntry>, io::Error> {
    let filepath = "/etc/passwd";
    let mut entries = Vec::new();

    for line in fs::read_to_string(filepath)?.lines() {
        let parts: Vec<&str> = line.split(":").collect();
        if parts.len() < 7 {
            continue;
        }

        let uid: u32 = match parts.get(2).unwrap().parse() {
            Ok(u) => u,
            Err(_) => continue,
        };

        let gid: u32 = match parts.get(3).unwrap().parse() {
            Ok(u) => u,
            Err(_) => continue,
        };

        entries.push(PasswordEntry {
            name: parts.get(0).unwrap().to_string(),
            enc_password: parts.get(1).unwrap().to_string(),
            uid,
            gid,
            comment: parts.get(4).unwrap().to_string(),
            home: parts.get(5).unwrap().to_string(),
            command: parts.get(6).unwrap().to_string(),
        });
    }

    return Ok(entries);
}

// Devices names from:
// https://mirrors.mit.edu/kernel/linux/docs/lanana/device-list/devices-2.6.txt
pub fn dev_t_to_name(dev: u64) -> Option<String> {
    let major = unsafe { libc::major(dev) };
    let minor = unsafe { libc::minor(dev) };

    match major {
        4 => {
            if minor < 64 {
                return Some(format!("/dev/tty{}", minor));
            }

            return Some(format!("/dev/ttyS{}", minor - 64));
        }
        136..=143 => return Some(format!("/dev/pts/{}", minor)),

        _ => None,
    }
}


// https://stackoverflow.com/questions/37498864/finding-executable-in-path-with-rust
pub fn find_in_path<P>(exe_name: P) -> Option<String>
where
    P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(&exe_name);
                if full_path.is_file() {
                    Some(full_path.into_os_string().into_string().unwrap())
                } else {
                    None
                }
            })
            .next()
    })
}
