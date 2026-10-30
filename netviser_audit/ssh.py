"""Runs the collector script locally or on a remote host over OpenSSH."""
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple

LOCAL = "local"


@dataclass
class RunOptions:
    identity: Optional[str] = None
    port: Optional[int] = None
    connect_timeout: int = 8
    timeout: int = 25
    sudo: bool = False


def valid_target(target: str) -> bool:
    # A leading "-" would be parsed by ssh as an option; whitespace and control
    # characters have no place in an SSH destination.
    return bool(target) and not target.startswith("-") and not any(
        c.isspace() or ord(c) < 32 or ord(c) == 127 for c in target)


def build_command(target: str, opts: RunOptions) -> List[str]:
    shell = "sudo -n sh -s" if opts.sudo else "sh -s"
    if target == LOCAL:
        return shell.split()
    command = ["ssh", "-T",
               "-o", "BatchMode=yes",
               "-o", "ConnectTimeout=%d" % opts.connect_timeout,
               "-o", "StrictHostKeyChecking=accept-new"]
    if opts.identity:
        command += ["-i", opts.identity]
    if opts.port:
        command += ["-p", str(opts.port)]
    return command + ["--", target, shell]


def run(target: str, script: str, opts: RunOptions) -> Tuple[Optional[str], Optional[str]]:
    """Return (stdout, None) on success or (None, error message)."""
    if target != LOCAL and not valid_target(target):
        return None, "invalid SSH target"
    try:
        proc = subprocess.run(build_command(target, opts), input=script, text=True,
                              capture_output=True, timeout=opts.timeout)
    except subprocess.TimeoutExpired:
        return None, "timed out after %ds" % opts.timeout
    except OSError as exc:
        return None, str(exc)[:500]
    if proc.returncode != 0:
        return None, (proc.stderr.strip() or "exit status %d" % proc.returncode)[-500:]
    return proc.stdout, None
