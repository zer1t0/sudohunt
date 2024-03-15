# sudohunt

Steal sudo from other user sessions. This tool allows to inject a sudo
timestamp record to allow the current session to use sudo.

Additionally, sudohunt can interact with sudoers timestamp files, located in
`/run/sudo/ts`. The timestamp files description can be found in
[sudoers_timestamp(5)](https://www.sudo.ws/docs/man/sudoers_timestamp.man/).

The tool include several commands:

- **read**: Show the contents of the timestamp files.
- **write**: Write a new record in timestamp files to give an user session
  sudo powers.
- **inject**: Injects a command in other user sessions trying to get sudo.

## When to use

In case you can access to a machine as an user which can use sudo, but requires
a password that you don't know. For example, you have can connect with an SSH key.

In case another person is logged with the same user and it is using sudo, you
can try to inject code into her session to give sudo to your session.

This tool requires that `ptrace` syscall is allowed to trace processes in other
sessions. This usually means that the value of
`/proc/sys/kernel/yama/ptrace_scope` file is 0, which is the default in distros
like Debian.


## How injection works

The following steps offers a summary (you can find extra details in the code)
of how *inject* command works:

1. Attach to a process in a different session (but same uid)
2. Force that process to execute a fork syscall
3. Attach to the child process
4. Detach from parent process (so we don't disrupt the original process)
5. Prepare the process to execute an execve syscall in next instruction
6. Detach from the child process making it execute the execve syscall

It is important to detach before the execve syscall happens since traced
processes are not able to spawn binaries with the setuid (like sudo) correctly.

```
  session: 1001                session: 1337
.-----------------.  1. attach   .------.
| sudohunt inject |------------->| bash |
'-----------------'  4. detach   '------'
                |                   |
                |                   | 2.fork
                |                   v
                |  3. attach     .------.
                '--------------->| bash |
                   5. detach     '------'
                                    |
                                    | 6. execve
                                    v
                     .--------------------------------.
                     | sudo sudohunt write --pid 1001 |
                     '--------------------------------'
```

Once the injection was performed the final sudo will success if sudo is already
enabled for the target session. If success in sudo, the default command will
give sudo to the original session.

## TODOs
- Add compatibility with x86 (32 bits)
- Add compatibility with ARM x64

- Support old sudo versions

## Disclaimer

I expect you know this, but... use this tool only in systems you are allowed to.
This is for educational purposes and I'm not responsible for the bad use of
this tool.
