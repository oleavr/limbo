#!/usr/bin/env python3

import ctypes
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

NAME_MAX = 128
FRAMES = {}
DEFINES = {}


def main():
    limbo, broker, header, outdir = sys.argv[1:5]
    read_header(header)
    outdir = Path(outdir).resolve()
    ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)
    broker_and_launchd(broker, outdir)
    broker_and_stand_in(broker, outdir)
    launchd_and_stand_in(limbo, outdir)
    print("ok")


def read_header(path):
    text = Path(path).read_text()
    body = text[text.index("enum broker_frame_type {"):]
    body = body[:body.index("};")]
    for number, name in enumerate(re.findall(r"\b(BROKER_[A-Z_]+),", body)):
        FRAMES[name[len("BROKER_"):]] = number
    DEFINES["DEADLINE"] = int(re.search(
        r"#define LIMBO_LAUNCHD_DEADLINE_MS\s+(\d+)", text).group(1)) / 1000


def check(condition, what):
    if not condition:
        print(f"FAILED: {what}")
        raise SystemExit(1)


def frame(kind, payload=b""):
    return struct.pack("II", FRAMES[kind], len(payload)) + payload


def receive(sock, timeout=10.0):
    sock.settimeout(timeout)
    try:
        data = sock.recv(1 << 20)
    except (socket.timeout, ConnectionResetError):
        return None
    if len(data) < 8:
        return None
    kind, length = struct.unpack("II", data[:8])
    return kind, data[8:8 + length]


def answer_of(sock, kind, what, unwanted=()):
    while True:
        got = receive(sock)
        check(got is not None, f"{what}: answered")
        check(got[0] not in [FRAMES[name] for name in unwanted],
              f"{what}: no {unwanted} before the answer")
        if got[0] == FRAMES[kind]:
            return got[1]


def name_field(name):
    return name.encode().ljust(NAME_MAX, b"\0")


def stat_fields(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None


def children(pid):
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            fields = stat_fields(entry.name)
            if fields is not None and int(fields[1]) == pid:
                found.append(int(entry.name))
    return found


def descendants(pid):
    found = []
    for child in children(pid):
        found += [child] + descendants(child)
    return found


def running(pid):
    fields = stat_fields(pid)
    return fields is not None and fields[0] != "Z"


class Tree:
    def __init__(self, process):
        self.process = process

    def __enter__(self):
        return self.process

    def __exit__(self, *exc):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        for _ in range(100):
            left = descendants(os.getpid())
            if not left:
                break
            for pid in left:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            while True:
                try:
                    if os.waitpid(-1, os.WNOHANG)[0] == 0:
                        break
                except ChildProcessError:
                    break
            time.sleep(0.05)


def connect(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sock.connect(str(path))
    return sock


def hello(sock):
    sock.send(frame("HELLO", struct.pack("I", 0)))
    return struct.unpack("Ii", answer_of(sock, "WELCOME", "a hello")[:8])


def start_broker(broker, path, env=None):
    if path.exists():
        path.unlink()
    process = subprocess.Popen([broker, str(path)], env=env,
                               stderr=subprocess.PIPE, text=True)
    for _ in range(200):
        if process.poll() is not None:
            break
        try:
            connect(path).close()
            break
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.05)
    return process


def broker_and_launchd(broker, outdir):
    path = outdir / "launchd-broker.sock"
    with Tree(start_broker(broker, path)) as process:
        launchd = [pid for pid in children(process.pid)
                   if Path(f"/proc/{pid}/cmdline").read_bytes()
                   .startswith(b"limbo-launchd\0")]
        check(len(launchd) == 1, "the broker has one limbo-launchd")
        launchd = launchd[0]
        check(Path(f"/proc/{launchd}/comm").read_text().strip()
              == "limbo-launchd", "it is named limbo-launchd")

        fd = Path(f"/proc/{launchd}/cmdline").read_bytes().split(b"\0")[1]
        flags = re.search(r"flags:\s+(\d+)", Path(
            f"/proc/{launchd}/fdinfo/{fd.decode()}").read_text()).group(1)
        check(int(flags, 8) & os.O_CLOEXEC,
              "limbo-launchd's connection is closed in what it starts")

        quiet = connect(path)
        guest = connect(path)
        check(hello(guest)[1] == launchd,
              "a guest is told limbo-launchd's pid")
        guest.close()
        quiet.send(frame("LOOKUP", name_field("com.limbo.test.launchd.none")
                         + struct.pack("I", 0)))
        answer = receive(quiet)
        check(answer is not None and answer[0] == FRAMES["LOOKUP_REPLY"],
              f"a connection that said no hello is told of no guest's going: "
              f"{answer and answer[0]}")
        quiet.close()

        process.kill()
        process.wait()
        for _ in range(100):
            if not running(launchd):
                break
            time.sleep(0.05)
        check(not running(launchd), "limbo-launchd goes with the broker")


STAND_IN = r'''#!/usr/bin/env python3
import time
time.sleep(600)
'''


def broker_and_stand_in(broker, outdir):
    folder = outdir / "launchd-stand-in"
    if folder.exists():
        for entry in folder.iterdir():
            entry.unlink()
    else:
        folder.mkdir()
    (folder / "limbo-broker").write_bytes(Path(broker).read_bytes())
    (folder / "limbo-broker").chmod(0o755)
    (folder / "limbo").write_text(STAND_IN)
    (folder / "limbo").chmod(0o755)
    path = folder / "broker.sock"
    started = time.monotonic()
    with Tree(start_broker(folder / "limbo-broker", path)) as process:
        stand_in = None
        for _ in range(100):
            stand_in = (children(process.pid) or [None])[0]
            if stand_in is not None:
                break
            time.sleep(0.05)
        try:
            status = process.wait(timeout=DEFINES["DEADLINE"] + 10)
        except subprocess.TimeoutExpired:
            check(False, "the broker gives up on a limbo-launchd that "
                  "never loads")
        waited = time.monotonic() - started
        said = process.stderr.read()
        check(status != 0 and "did not load" in said,
              f"the broker says so and exits: {status}, {said}")
        check(DEFINES["DEADLINE"] - 1 <= waited,
              f"it gave it its time: {waited:.1f} s")
        check(stand_in is not None and not running(stand_in),
              "and limbo-launchd went with it")


def launchd_and_stand_in(limbo, outdir):
    def start(between):
        sock, theirs = socket.socketpair(socket.AF_UNIX,
                                         socket.SOCK_SEQPACKET)
        command = ["limbo-launchd", str(theirs.fileno())]
        if between:
            process = subprocess.Popen(
                [sys.executable, "-c",
                 "import subprocess, sys; sys.exit(subprocess.call("
                 "sys.argv[2:], executable=sys.argv[1], "
                 "pass_fds=[int(sys.argv[3])]))", limbo, *command],
                pass_fds=[theirs.fileno()])
        else:
            process = subprocess.Popen(command, executable=limbo,
                                       pass_fds=[theirs.fileno()])
        theirs.close()
        return sock, process

    sock, process = start(True)
    with Tree(process):
        check(process.wait(timeout=10) == 1,
              "limbo-launchd does not start for one that isn't its parent")

    sock, process = start(False)
    with Tree(process):
        got = receive(sock)
        check(got is not None and got[0] == FRAMES["JOBS_LOADED"],
              f"limbo-launchd says it has loaded: {got}")
        sock.close()
        status = process.wait(timeout=10)
        check(status != 0, f"limbo-launchd fails when the broker goes: "
              f"{status}")


if __name__ == "__main__":
    main()
