#!/usr/bin/env python3
"""WHY: Runs the packaged Spring Boot fixture and records class loads through a real HTTP request."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


def main() -> int:
    java, jar, trace, output = sys.argv[1:]
    port = free_port()
    command = [
        java,
        f"-Xlog:class+load=info:file={trace}",
        "-jar",
        jar,
        f"--server.port={port}",
    ]
    with Path(output).open("w", encoding="utf-8") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            body = read_greeting(process, port, Path(output))
            if body != b'{"message":"hello"}':
                raise RuntimeError(f"unexpected endpoint response: {body!r}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return 0


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def read_greeting(process: subprocess.Popen[str], port: int, log_path: Path) -> bytes:
    deadline = time.monotonic() + 60
    url = f"http://127.0.0.1:{port}/api/hello"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Spring Boot exited early; see {log_path}")
        try:
            with urlopen(url, timeout=2) as response:
                return response.read()
        except (TimeoutError, URLError):
            time.sleep(0.25)
    raise RuntimeError(f"Spring Boot did not serve the endpoint; see {log_path}")


if __name__ == "__main__":
    raise SystemExit(main())
