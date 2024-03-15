use errno::errno;
pub use errno::Errno;
pub use libc::SIGKILL;
use libc::{self, c_ulonglong, user_regs_struct};
use log;
use std::io::{Read, SeekFrom, Write};
use std::{fmt, fs::File, io::Seek};

#[derive(Debug)]
pub enum TraceError {
    AttachError(i32, Errno),
    DetachError(i32, Errno),
    GetRegsError(i32, Errno),
    ReadMemoryError(i32, Errno),
    SetRegsError(i32, Errno),
    SignalError(i32, Errno),
    SingleStepError(i32, Errno),
    SyscallNotFoundError(i32),
    WaitError,
    WriteMemoryError(i32, Errno),
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttachError(pid, errno) => {
                write!(f, "Attach Error on pid {}: {}", pid, errno)
            }
            Self::DetachError(pid, errno) => {
                write!(f, "Detach Error on pid {}: {}", pid, errno)
            }
            Self::GetRegsError(pid, errno) => {
                write!(f, "Get registers Error on pid {}: {}", pid, errno)
            }
            Self::ReadMemoryError(pid, errno) => {
                write!(f, "Read memory Error on pid {}: {}", pid, errno)
            }
            Self::SetRegsError(pid, errno) => {
                write!(f, "Set registers Error on pid {}: {}", pid, errno)
            }
            Self::SignalError(pid, errno) => {
                write!(f, "Error sending signal to pid {}: {}", pid, errno)
            }
            Self::SingleStepError(pid, errno) => {
                write!(f, "Single step Error on pid {}: {}", pid, errno)
            }
            Self::SyscallNotFoundError(pid) => {
                write!(f, "Unable to found syscall in pid {}", pid)
            }
            Self::WaitError => write!(f, "Wait Error"),
            Self::WriteMemoryError(pid, errno) => {
                write!(f, "Write memory Error on pid {}: {}", pid, errno)
            }
        }
    }
}

const __NR_CLOSE: u64 = 3;
const __NR_CLONE: u64 = 56;
const __NR_FORK: u64 = 57;
const __NR_MMAP: u64 = 9;
const __NR_MUNMAP: u64 = 11;
const __NR_EXECVE: u64 = 59;

pub struct TraceSession {
    pid: i32,
    syscall_addr: u64,
}

impl Drop for TraceSession {
    fn drop(&mut self) {
        let _ = detach_process(self.pid);
    }
}

// just get TraceSession out of scope it is dropped
pub fn detach_session(_: TraceSession) -> () {
    return ();
}

pub fn init_trace_session(pid: i32) -> Result<TraceSession, TraceError> {
    attach_process(pid)?;

    match get_syscall_addr(pid) {
        Ok(addr) => {
            let session = TraceSession {
                pid,
                syscall_addr: addr,
            };
            return Ok(session);
        }
        Err(err) => {
            detach_process(pid)?;
            return Err(err);
        }
    }
}

pub fn init_forked_trace_session(pid: i32) -> Result<TraceSession, TraceError> {
    let parent_session = init_trace_session(pid)?;
    let result = fork_session(&parent_session);
    return result;
}

pub fn fork_session(
    session: &TraceSession,
) -> Result<TraceSession, TraceError> {
    let pid = exec_fork(session.pid, session.syscall_addr)?;
    return init_trace_session(pid as i32);
}

fn exec_fork(pid: i32, sc_addr: u64) -> Result<u64, TraceError> {
    return execute_syscall(pid, sc_addr, __NR_FORK, 0, 0, 0, 0, 0, 0);
}

const X64_PTR_SIZE: usize = 8;

pub fn prepare_execve_from_local(
    session: &TraceSession,
    filename: &str,
    argv: &Vec<String>,
    envp: &Vec<String>,
) -> Result<(), TraceError> {
    let filename_c_size = filename.len() + 1;

    let argv_ptrs_size = (argv.len() + 1) * X64_PTR_SIZE;
    let mut argv_strings_c_size = 0;
    for arg in argv.iter() {
        argv_strings_c_size += arg.as_bytes().len() + 1;
    }

    let envp_ptrs_size = (envp.len() + 1) * X64_PTR_SIZE;
    let mut envp_strings_c_size = 0;
    for envv in envp.iter() {
        envp_strings_c_size += envv.as_bytes().len() + 1;
    }

    let total_size = filename_c_size
        + argv_ptrs_size
        + argv_strings_c_size
        + envp_ptrs_size
        + envp_strings_c_size;

    let remote_buffer = exec_mmap(
        session.pid,
        session.syscall_addr,
        0,
        total_size.try_into().unwrap(),
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    )?;

    let mut target_addr = remote_buffer;
    let filename_remote_addr = target_addr;

    log::debug!(
        "Allocated memory map on pid {} at address 0x{:x}",
        session.pid,
        remote_buffer
    );

    let mut local_buffer: Vec<u8> = Vec::new();
    local_buffer.extend_from_slice(filename.as_bytes());
    local_buffer.push(0);

    target_addr += local_buffer.len() as u64;

    let argv_remote_addr = target_addr;
    target_addr += argv_ptrs_size as u64;

    for arg in argv {
        local_buffer.extend_from_slice(&target_addr.to_le_bytes());
        target_addr += arg.as_bytes().len() as u64 + 1;
    }
    local_buffer.extend_from_slice(&(0 as u64).to_le_bytes());

    for arg in argv {
        local_buffer.extend_from_slice(arg.as_bytes());
        local_buffer.push(0);
    }

    let envp_remote_addr = target_addr;
    target_addr += envp_ptrs_size as u64;

    for envv in envp {
        local_buffer.extend_from_slice(&target_addr.to_le_bytes());
        target_addr += envv.as_bytes().len() as u64 + 1;
    }
    local_buffer.extend_from_slice(&(0 as u64).to_le_bytes());

    for envv in envp {
        local_buffer.extend_from_slice(envv.as_bytes());
        local_buffer.push(0);
    }

    write_memory(session.pid, remote_buffer, &local_buffer)?;

    let ret = prepare_execve(
        session.pid,
        session.syscall_addr,
        filename_remote_addr,
        argv_remote_addr,
        envp_remote_addr,
    );
    if ret.is_err() {
        let _ = exec_munmap(
            session.pid,
            session.syscall_addr,
            remote_buffer,
            local_buffer.len() as u64,
        );
        return ret;
    }

    return Ok(());
}

pub fn execute_close(
    session: &TraceSession,
    fd: i32,
) -> Result<(), TraceError> {
    exec_close(session.pid, session.syscall_addr, fd)?;
    return Ok(());
}

pub fn send_signal(
    session: &TraceSession,
    signal: i32,
) -> Result<(), TraceError> {
    let res = unsafe { libc::kill(session.pid, signal) };
    if res == -1 {
        return Err(TraceError::SignalError(session.pid, errno()));
    }

    return Ok(());
}

fn prepare_execve(
    pid: i32,
    sc_addr: u64,
    filename_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) -> Result<(), TraceError> {
    set_syscall_regs(
        pid,
        sc_addr,
        __NR_EXECVE,
        filename_addr,
        argv_addr,
        envp_addr,
        0,
        0,
        0,
    )?;
    return Ok(());
}

fn exec_close(pid: i32, sc_addr: u64, fd: i32) -> Result<u64, TraceError> {
    return execute_syscall(pid, sc_addr, __NR_CLOSE, fd as u64, 0, 0, 0, 0, 0);
}

fn exec_mmap(
    pid: i32,
    sc_addr: u64,
    addr: u64,
    length: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<u64, TraceError> {
    return execute_syscall(
        pid,
        sc_addr,
        __NR_MMAP,
        addr,
        length,
        prot as u64,
        flags as u64,
        fd as u64,
        offset as u64,
    );
}

fn exec_munmap(
    pid: i32,
    sc_addr: u64,
    addr: u64,
    length: u64,
) -> Result<u64, TraceError> {
    return execute_syscall(
        pid,
        sc_addr,
        __NR_MUNMAP,
        addr,
        length,
        0,
        0,
        0,
        0,
    );
}

fn execute_syscall(
    pid: i32,
    sc_addr: u64,
    sc_number: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
) -> Result<u64, TraceError> {
    let backup_regs = ptrace_getregs(pid)?;

    set_syscall_regs(pid, sc_addr, sc_number, rdi, rsi, rdx, r10, r8, r9)?;

    if let Err(e) = singlestep(pid) {
        ptrace_setregs(pid, &backup_regs)?;
        return Err(e);
    }

    let result = rax(pid)?;

    ptrace_setregs(pid, &backup_regs)?;

    return Ok(result);
}

fn set_syscall_regs(
    pid: i32,
    sc_addr: u64,
    sc_number: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
) -> Result<(), TraceError> {
    let mut regs = ptrace_getregs(pid)?;

    regs.rip = sc_addr;
    regs.rax = sc_number;
    regs.rdi = rdi;
    regs.rsi = rsi;
    regs.rdx = rdx;
    regs.r10 = r10;
    regs.r8 = r8;
    regs.r9 = r9;

    ptrace_setregs(pid, &regs)?;

    return Ok(());
}

fn rax(pid: i32) -> Result<u64, TraceError> {
    let regs = ptrace_getregs(pid)?;
    return Ok(regs.rax);
}

fn singlestep(pid: i32) -> Result<(), TraceError> {
    ptrace_singlestep(pid)?;
    wait_for_singlestep(pid)?;
    return Ok(());
}

fn wait_for_singlestep(pid: i32) -> Result<(), TraceError> {
    let mut process_status = 0;
    let res =
        unsafe { libc::waitpid(pid, &mut process_status, libc::WUNTRACED) };
    if res != pid {
        return Err(TraceError::WaitError);
    }

    if !was_stopped_by_sigtrap(process_status) {
        return Err(TraceError::WaitError);
    }

    return Ok(());
}

fn was_stopped_by_sigtrap(status: i32) -> bool {
    return libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP;
}

const X64_SYSCALL_SIZE: usize = 2;
const X64_SYSCALL_OPCODES: &[u8] = &[0x0f, 0x05];

fn get_syscall_addr(pid: i32) -> Result<c_ulonglong, TraceError> {
    let pc = get_program_counter(pid)?;

    let syscall_addr = pc - 2;

    let syscall_bytes = read_memory(pid, syscall_addr, X64_SYSCALL_SIZE)?;
    if syscall_bytes != X64_SYSCALL_OPCODES {
        return Err(TraceError::SyscallNotFoundError(pid));
    }

    return Ok(syscall_addr);
}

fn read_memory(
    pid: i32,
    start_addr: c_ulonglong,
    size: usize,
) -> Result<Vec<u8>, TraceError> {
    let filepath = format!("/proc/{}/mem", pid);

    let mut f = File::open(filepath).map_err(|e| {
        TraceError::ReadMemoryError(pid, Errno(e.raw_os_error().unwrap_or(0)))
    })?;

    f.seek(SeekFrom::Start(start_addr)).map_err(|e| {
        TraceError::ReadMemoryError(pid, Errno(e.raw_os_error().unwrap_or(0)))
    })?;

    let mut bytes = vec![0; size];

    f.read_exact(&mut bytes).map_err(|e| {
        TraceError::ReadMemoryError(pid, Errno(e.raw_os_error().unwrap_or(0)))
    })?;

    return Ok(bytes);
}

fn write_memory(
    pid: i32,
    start_addr: u64,
    bytes: &[u8],
) -> Result<(), TraceError> {
    let filepath = format!("/proc/{}/mem", pid);

    let mut f = File::options()
        .write(true)
        .truncate(false)
        .open(filepath)
        .map_err(|e| {
            TraceError::WriteMemoryError(
                pid,
                Errno(e.raw_os_error().unwrap_or(0)),
            )
        })?;

    f.seek(SeekFrom::Start(start_addr)).map_err(|e| {
        TraceError::WriteMemoryError(pid, Errno(e.raw_os_error().unwrap_or(0)))
    })?;

    f.write_all(bytes).map_err(|e| {
        TraceError::WriteMemoryError(pid, Errno(e.raw_os_error().unwrap_or(0)))
    })?;

    return Ok(());
}

fn get_program_counter(pid: i32) -> Result<c_ulonglong, TraceError> {
    let regs = ptrace_getregs(pid)?;
    return Ok(regs.rip);
}

fn detach_process(pid: i32) -> Result<(), TraceError> {
    log::debug!("Detaching from process {}", pid);
    if let Err(e) = ptrace_detach(pid) {
        log::debug!("Ptrace detach error: {}", e);
        return Err(e);
    }
    return Ok(());
}

fn attach_process(pid: i32) -> Result<(), TraceError> {
    // TODO: Check target process bits

    ptrace_attach(pid)?;

    let mut process_status = 0;
    let res =
        unsafe { libc::waitpid(pid, &mut process_status, libc::WUNTRACED) };
    if res != pid {
        return Err(TraceError::WaitError);
    }

    if !libc::WIFSTOPPED(process_status) {
        return Err(TraceError::WaitError);
    }

    return Ok(());
}

fn ptrace_attach(pid: i32) -> Result<(), TraceError> {
    let res = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
    if res == -1 {
        return Err(TraceError::AttachError(pid, errno()));
    }
    return Ok(());
}

fn ptrace_detach(pid: i32) -> Result<(), TraceError> {
    let res = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
    if res == -1 {
        return Err(TraceError::DetachError(pid, errno()));
    }
    return Ok(());
}

fn ptrace_singlestep(pid: i32) -> Result<(), TraceError> {
    let res = unsafe { libc::ptrace(libc::PTRACE_SINGLESTEP, pid, 0, 0) };
    if res == -1 {
        return Err(TraceError::SingleStepError(pid, errno()));
    }
    return Ok(());
}

fn ptrace_getregs(pid: i32) -> Result<user_regs_struct, TraceError> {
    let mut regs = empty_user_regs_struct();
    let res = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) };
    if res == -1 {
        return Err(TraceError::GetRegsError(pid, errno()));
    }
    return Ok(regs);
}

fn ptrace_setregs(pid: i32, regs: &user_regs_struct) -> Result<(), TraceError> {
    let res = unsafe { libc::ptrace(libc::PTRACE_SETREGS, pid, 0, regs) };
    if res == -1 {
        return Err(TraceError::SetRegsError(pid, errno()));
    }
    return Ok(());
}

// fn ptrace_peektext(pid: i32, addr: c_void) -> Result<u64, TraceError> {
//     let res = unsafe { libc::ptrace(libc::PTRACE_PEEKTEXT, pid, addr) };
//     if res == -1 && errno().0 != 0 {
//         return Err(TraceError::ReadWordError(pid, errno()));
//     }
//     return Ok(res as u64);
// }

#[cfg(target_arch = "x86_64")]
fn empty_user_regs_struct() -> user_regs_struct {
    user_regs_struct {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0,
        eflags: 0,
        rsp: 0,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}
