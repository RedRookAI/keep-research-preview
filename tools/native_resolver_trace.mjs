/** Diagnostic observed-trace contract. This is not kernel syscall enforcement. */
export function assertResolverTrace(tracedEffects) {
  const allowedSyscalls = new Set(["arch_prctl", "brk", "close", "execve", "exit_group", "fchmod", "fcntl",
    "fstat", "fstatfs", "lseek", "memfd_create", "mmap", "mprotect", "munmap", "open", "openat2", "poll",
    "read", "rt_sigaction", "rt_sigprocmask", "set_tid_address", "sigaltstack", "statx", "write",
    // Existing held-inode custody uses own PID and effective UID to check /proc/SELF/fd.
    "getpid", "geteuid"]);
  const calls = [...tracedEffects.matchAll(/^(?:\d+\s+)?([a-z_][a-z0-9_]*)\(/gm)].map(match => match[1]);
  if (calls.length === 0) throw new Error("resolver syscall trace is empty or unparseable");
  const unexpected = calls.find(call => !allowedSyscalls.has(call));
  if (unexpected) throw new Error(`resolver performed non-allowlisted syscall ${unexpected}: ${tracedEffects}`);
  if (/\bopen(?:at2?)?\([^\n]*(?:O_WRONLY|O_RDWR|O_CREAT)/.test(tracedEffects))
    throw new Error(`resolver opened a pathname for writing: ${tracedEffects}`);
  if (/\/dev\/kvm|\/sys\/fs\/cgroup|credential|evidence/i.test(tracedEffects))
    throw new Error(`resolver touched authority-bearing or evidence state: ${tracedEffects}`);
  if ((tracedEffects.match(/\bexecve\s*\(/g) ?? []).length !== 1)
    throw new Error(`resolver process trace has unexpected exec count: ${tracedEffects}`);
}
