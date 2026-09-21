"""QEMU VM connector — SSH, serial console, and telnet."""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class QemuConnectionConfig(BaseModel):
    method: str = "serial"  # "ssh" | "serial" | "telnet"
    host: str = "127.0.0.1"
    port: int = 2222
    username: str = "root"
    password: str = ""
    serial_device: str = ""  # "/dev/pts/3" or "/tmp/qemu-serial.sock"
    timeout: float = 15.0


@dataclass
class ShellResult:
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    success: bool = False
    timed_out: bool = False


# Blocked destructive commands
_BLOCKED_PATTERNS = [
    "rm -rf /", "mkfs.", "dd if=", "reboot", "poweroff",
    "halt", "init 0", "init 6", "shutdown",
]


def _is_command_safe(command: str) -> tuple[bool, str]:
    cmd_lower = command.strip().lower()
    for pat in _BLOCKED_PATTERNS:
        if pat in cmd_lower:
            return False, f"Blocked destructive command: {pat}"
    return True, ""


class QemuConnector(ABC):
    def __init__(self, config: QemuConnectionConfig):
        self.config = config
        self._connected = False

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def exec(self, command: str, timeout: float = 15.0) -> ShellResult: ...

    @abstractmethod
    def close(self) -> None: ...

    def ensure_connected(self) -> None:
        if not self._connected:
            self.connect()


class SshConnector(QemuConnector):
    """SSH connection via paramiko."""

    def __init__(self, config: QemuConnectionConfig):
        super().__init__(config)
        self._client = None

    def connect(self) -> None:
        import paramiko
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=self.config.host,
            port=self.config.port,
            username=self.config.username,
            password=self.config.password or None,
            timeout=self.config.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self._connected = True
        logger.info(f"SSH connected to {self.config.host}:{self.config.port}")

    def exec(self, command: str, timeout: float = 15.0) -> ShellResult:
        safe, reason = _is_command_safe(command)
        if not safe:
            return ShellResult(exit_code=-1, stderr=reason)

        self.ensure_connected()
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            return ShellResult(
                exit_code=exit_code,
                stdout=stdout.read().decode(errors="ignore")[:5000],
                stderr=stderr.read().decode(errors="ignore")[:2000],
                success=exit_code == 0,
            )
        except Exception as e:
            return ShellResult(exit_code=-1, stderr=str(e), timed_out="timeout" in str(e).lower())

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
        self._connected = False


class SerialConnector(QemuConnector):
    """Serial console via pexpect. Supports unix sockets and /dev/pts devices."""

    def __init__(self, config: QemuConnectionConfig):
        super().__init__(config)
        self._child = None

    def connect(self) -> None:
        import pexpect

        device = self.config.serial_device
        if not device:
            raise ValueError("serial_device is required for serial method")

        if device.endswith(".sock") or "sock" in device:
            cmd = f"socat - UNIX-CONNECT:{device}"
        elif device.startswith("/dev/"):
            cmd = f"cu -l {device} -s 115200"
        else:
            cmd = f"socat - UNIX-CONNECT:{device}"

        self._child = pexpect.spawn(cmd, timeout=10, encoding=None)
        # Flush buffer and wait for prompt
        time.sleep(1)
        self._child.sendline(b"")
        self._child.expect([rb"[#$>]\s*", pexpect.TIMEOUT], timeout=5)
        # Flush any remaining buffered output
        if self._child.buffer:
            self._child.buffer = b""
        self._connected = True
        logger.info(f"Serial connected to {device}")

    def exec(self, command: str, timeout: float = 15.0) -> ShellResult:
        import pexpect
        import random

        safe, reason = _is_command_safe(command)
        if not safe:
            return ShellResult(exit_code=-1, stderr=reason)

        self.ensure_connected()
        try:
            # Use unique markers: START marks begin of output, END marks end with exit code
            tag = f"{random.randint(100000, 999999)}"
            start_marker = f"__S{tag}__"
            end_marker = f"__E{tag}__"
            # Wrap command: print START, run command, print END with exit code
            full_cmd = f"echo {start_marker}; ({command}); echo {end_marker}_$?"
            self._child.sendline(full_cmd.encode())

            # Wait for end marker
            end_pattern = re.escape(end_marker).encode() + rb"_(\d+)"
            idx = self._child.expect(
                [end_pattern, pexpect.TIMEOUT, pexpect.EOF],
                timeout=timeout,
            )

            raw = self._child.before.decode(errors="ignore") if self._child.before else ""

            # Extract exit code BEFORE consuming prompt (which overwrites match)
            exit_code = -1
            if idx == 0 and self._child.match:
                try:
                    exit_code = int(self._child.match.group(1))
                except (IndexError, AttributeError, ValueError):
                    # Fallback: search for exit code in raw output
                    exit_match = re.search(rb'__E\d+___(\d+)', raw.encode() if isinstance(raw, str) else raw)
                    exit_code = int(exit_match.group(1)) if exit_match else -1

            # Consume prompt after output
            self._child.expect([rb"[#$>]\s*", pexpect.TIMEOUT], timeout=3)
            # Flush buffer to prevent stale data
            if self._child.buffer:
                self._child.buffer = b""

            if idx == 0:
                # Normalize line endings
                text = raw.replace("\r\n", "\n").replace("\r", "\n")

                # Strategy: find all occurrences of start_marker, use the LAST one
                # (the first is the serial echo, the last is the actual output)
                start_pos = text.rfind(start_marker)
                end_pos = text.rfind(end_marker)

                if start_pos >= 0:
                    output = text[start_pos + len(start_marker):]
                    if end_pos > start_pos:
                        output = text[start_pos + len(start_marker):end_pos]
                    # Strip leading/trailing whitespace
                    cleaned = output.strip()
                else:
                    # No start marker found - return raw (stripped of echo)
                    lines = [l for l in text.split("\n")
                             if l.strip() and full_cmd[:30] not in l]
                    cleaned = "\n".join(lines).strip()

                return ShellResult(
                    exit_code=exit_code,
                    stdout=cleaned[:5000],
                    success=exit_code == 0,
                )
            elif idx == 1:
                return ShellResult(exit_code=-1, stdout=raw[:2000], timed_out=True)
            else:
                return ShellResult(exit_code=-1, stderr="EOF", stdout=raw[:2000])

        except Exception as e:
            return ShellResult(exit_code=-1, stderr=str(e), timed_out="timeout" in str(e).lower())

    def close(self) -> None:
        if self._child:
            self._child.close()
            self._child = None
        self._connected = False


class TelnetConnector(QemuConnector):
    """Telnet connection via stdlib telnetlib."""

    def __init__(self, config: QemuConnectionConfig):
        super().__init__(config)
        self._tn = None

    def connect(self) -> None:
        import telnetlib
        self._tn = telnetlib.Telnet(self.config.host, self.config.port, timeout=self.config.timeout)
        # Wait for prompt
        self._tn.read_until(b"# ", timeout=5)
        self._connected = True
        logger.info(f"Telnet connected to {self.config.host}:{self.config.port}")

    def exec(self, command: str, timeout: float = 15.0) -> ShellResult:
        import telnetlib

        safe, reason = _is_command_safe(command)
        if not safe:
            return ShellResult(exit_code=-1, stderr=reason)

        self.ensure_connected()
        try:
            marker = f"__SESAME_END_{id(command) % 10000}__"
            full_cmd = f"{command}; echo {marker}_$?\n"
            self._tn.write(full_cmd.encode())
            idx, match, text = self._tn.expect(
                [re.escape(marker).encode() + rb"_(\d+)"],
                timeout=timeout,
            )
            output = text.decode(errors="ignore")
            lines = output.split("\n")
            cleaned = "\n".join(lines[1:-1]).strip() if len(lines) > 2 else output.strip()

            exit_code = 0
            if match:
                exit_code = int(match.group(1))

            return ShellResult(
                exit_code=exit_code,
                stdout=cleaned[:5000],
                success=exit_code == 0,
            )
        except Exception as e:
            return ShellResult(exit_code=-1, stderr=str(e), timed_out="timeout" in str(e).lower())

    def close(self) -> None:
        if self._tn:
            self._tn.close()
            self._tn = None
        self._connected = False


def create_qemu_connector(config: QemuConnectionConfig) -> QemuConnector:
    if config.method == "ssh":
        return SshConnector(config)
    elif config.method == "serial":
        return SerialConnector(config)
    elif config.method == "telnet":
        return TelnetConnector(config)
    raise ValueError(f"Unknown QEMU connection method: {config.method}")


# Need import for SerialConnector.connect
import time  # noqa: E402
