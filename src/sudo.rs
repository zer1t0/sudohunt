
use std::process::Command;
use std::str;


pub const SUDO_VERSION_UID : &str = "1.9.15";

pub fn sudo_version() -> Result<String, String> {
    let output_bytes = Command::new("sudo")
        .arg("-V")
        .output()
        .map_err(|e| format!("Error executing sudo -V: {}", e))?
        .stdout;

    let lines = str::from_utf8(&output_bytes)
        .map_err(|e| format!("Error parsing sudo -V output: {}", e))?;

    let first_line = lines.split("\n").next().unwrap();
    let first_line_parts: Vec<&str> = first_line.split(" ").collect();

    match first_line_parts.get(2) {
        Some(version_str) => {
            return Ok(version_str.to_string());
        }
        None => return Err(format!("Unable to get sudo version from sudo -V")),
    }
}

pub fn parse_sudo_version(version_str: &str) -> Result<u64, String> {
    let parts: Vec<&str> = version_str.split(".").collect();
    if parts.len() != 3 {
        return Err(format!("Unable to parse sudo version"));
    }

    let major = parts[0]
        .parse::<u64>()
        .map_err(|_| format!("Unable to parse sudo major version"))?;

    let minor = parts[1]
        .parse::<u64>()
        .map_err(|_| format!("Unable to parse sudo minor version"))?;

    let release_parts: Vec<&str> = parts[2].split("p").collect();

    let release_major = release_parts[0]
        .parse::<u64>()
        .map_err(|_| format!("Unable to parse sudo release major version"))?;

    let release_minor = release_parts
        .get(1)
        .unwrap_or(&"0")
        .parse::<u64>()
        .map_err(|_| format!("Unable to parse sudo release minor version"))?;

    let version =
        release_minor + release_major * 100 + minor * 10000 + major * 1000000;

    return Ok(version);
}
