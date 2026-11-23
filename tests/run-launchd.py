#!/usr/bin/env python3

import ctypes
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

NAME_MAX = 128
AWAITED_DEMANDED = 0x1
DOMAIN_USER = 0

FRAMES = {}
DEFINES = {}
NOT_RUN = []


def read_header(path):
    text = Path(path).read_text()
    body = text[text.index("enum broker_frame_type {"):]
    body = re.sub(r"/\*.*?\*/", "", body[:body.index("};")], flags=re.S)
    for number, name in enumerate(re.findall(r"\b(BROKER_[A-Z_]+),", body)):
        FRAMES[name[len("BROKER_"):]] = number
    for name in ("LIMBO_LAUNCHD_STOP_MS",):
        DEFINES[name] = int(re.search(rf"#define {name}\s+(\d+)", text).group(1))
    DEFINES["STOP"] = DEFINES["LIMBO_LAUNCHD_STOP_MS"] / 1000
    DEFINES["DEADLINE"] = 4 * DEFINES["STOP"]


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


def gone(pid, seconds=5.0):
    for _ in range(int(seconds * 20)):
        if not running(pid):
            return True
        time.sleep(0.05)
    return False


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


def hello(sock, domain, uid):
    sock.send(frame("HELLO", struct.pack("II", domain, uid)))
    return struct.unpack("Ii", answer_of(sock, "WELCOME", "a hello")[:8])


def job_table(sysroot, jobs):
    return "".join(f"{name} user - - - {flags} - - 0 {service} bin/sleep 600\n"
                   for name, flags, service in jobs) if sysroot else ""


def with_sleep():
    sysroot = os.environ.get("LIMBO_SYSROOT")
    return sysroot if sysroot and (Path(sysroot) / "bin/sleep").exists() else None


def broker_and_launchd(broker, outdir):
    sysroot = with_sleep()
    if not sysroot:
        NOT_RUN.append("the real broker and limbo-launchd with jobs: a job "
                       "runs as limbo-launchd's child without its connection")
    table = outdir / "launchd-jobs.txt"
    table.write_text(job_table(sysroot, [
        ("com.limbo.test.launchd.sleep", "runatload", "-")]))
    path = outdir / "launchd-broker.sock"
    env = dict(os.environ, LIMBO_BROKER=str(path))

    def start(*table_argument):
        if path.exists():
            path.unlink()
        process = subprocess.Popen(
            [broker, str(path), "/dev/null", *table_argument], env=env)
        for _ in range(200):
            if process.poll() is not None:
                break
            try:
                connect(path).close()
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.05)
        return process

    with Tree(start(str(table))) as process:
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
        job = None
        for _ in range(200 if sysroot else 0):
            job = (children(launchd) or [None])[0]
            if job is not None:
                break
            time.sleep(0.05)
        if sysroot:
            check(job is not None and running(job), "the job runs")
            check(int(stat_fields(job)[1]) == launchd,
                  "the job is limbo-launchd's child")
            for _ in range(200):
                if Path(f"/proc/{job}/cmdline").read_bytes().startswith(
                        b"limbo\0"):
                    break
                time.sleep(0.05)
            connection = os.readlink(f"/proc/{launchd}/fd/{fd.decode()}")
            held = [os.readlink(entry) for entry in
                    Path(f"/proc/{job}/fd").iterdir()]
            check(connection.startswith("socket:") and connection not in held,
                  f"the job has not limbo-launchd's connection: {held}")

        quiet = connect(path)
        guest = connect(path)
        check(hello(guest, DOMAIN_USER, os.getuid())[1] == launchd,
              "a guest is told limbo-launchd's pid")
        guest.close()
        quiet.send(frame("LOOKUP", name_field("com.limbo.test.launchd.none")
                         + struct.pack("III", DOMAIN_USER, 0, 0)))
        answer = receive(quiet)
        check(answer is not None and answer[0] == FRAMES["LOOKUP_REPLY"],
              f"a connection that said no hello is told of no guest's going: "
              f"{answer and answer[0]}")
        quiet.close()

        process.kill()
        process.wait()
        check(job is None or gone(job), "the job stopped with the broker")


def look_up(sock, name):
    sock.send(frame("LOOKUP", name_field(name) + struct.pack(
        "I", DOMAIN_USER)))
    found, hidden, port = struct.unpack("IIQ", answer_of(
        sock, "LOOKUP_REPLY", f"a look-up of {name}")[:16])
    return port if found else None


STAND_IN = r'''#!/usr/bin/env python3
import os, time
if os.environ["LIMBO_TEST_STAND_IN"] == "never":
    time.sleep(600)
'''


def broker_and_stand_in(broker, outdir):
    folder = outdir / "launchd-stand-in"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir()
    shutil.copy(broker, folder / "limbo-broker")
    (folder / "limbo").write_text(STAND_IN)
    (folder / "limbo").chmod(0o755)
    table = folder / "jobs.txt"
    table.write_text("")
    path = folder / "broker.sock"

    def start(mode):
        if path.exists():
            path.unlink()
        env = dict(os.environ, LIMBO_TEST_STAND_IN=mode,
                   LIMBO_BROKER=str(path))
        return subprocess.Popen([folder / "limbo-broker", str(path),
                                 "/dev/null", str(table)], env=env,
                                stderr=subprocess.PIPE, text=True), env, \
            time.monotonic()

    def ends_the_system(process, started, why):
        try:
            status = process.wait(timeout=DEFINES["DEADLINE"] + 10)
        except subprocess.TimeoutExpired:
            check(False, f"the broker gives up on {why}")
        waited = time.monotonic() - started
        said = process.stderr.read()
        check(status != 0 and "did not load" in said,
              f"the broker says so and exits: {status}, {said}")
        check(DEFINES["DEADLINE"] - 1 <= waited,
              f"it gave it its time: {waited:.1f} s")

    process, env, started = start("never")
    with Tree(process):
        stand_in = None
        for _ in range(100):
            stand_in = (children(process.pid) or [None])[0]
            if stand_in is not None:
                break
            time.sleep(0.05)
        ends_the_system(process, started,
                        "a limbo-launchd that never loads its table")
        check(stand_in is not None and not running(stand_in),
              "and limbo-launchd went with it")


class StandInBroker:

    def __init__(self, limbo, table, outdir, between=False):
        self.sock, theirs = socket.socketpair(socket.AF_UNIX,
                                              socket.SOCK_SEQPACKET)
        command = ["limbo-launchd", str(theirs.fileno()), str(table)]
        if between:
            self.process = subprocess.Popen(
                [sys.executable, "-c",
                 "import subprocess, sys; sys.exit(subprocess.call("
                 "sys.argv[2:], executable=sys.argv[1], "
                 "pass_fds=[int(sys.argv[3])]))", limbo, *command],
                pass_fds=[theirs.fileno()])
        else:
            self.process = subprocess.Popen(command, executable=limbo,
                                            pass_fds=[theirs.fileno()])
        theirs.close()
        self.backlog = []

    def until(self, kind, timeout=10.0):
        for at, got in enumerate(self.backlog):
            if got[0] == FRAMES[kind]:
                del self.backlog[at]
                return got[1]
        while True:
            got = receive(self.sock, timeout)
            if got is None:
                check(False, f"limbo-launchd sends a {kind} frame")
            if got[0] == FRAMES[kind]:
                return got[1]
            self.backlog.append(got)

    def ends(self, timeout=None):
        try:
            return self.process.wait(timeout=timeout or DEFINES["DEADLINE"])
        except subprocess.TimeoutExpired:
            check(False, "limbo-launchd goes")


def launchd_and_stand_in(limbo, outdir):
    table = outdir / "launchd-alone-jobs.txt"
    table.write_text("")

    other = StandInBroker(limbo, table, outdir, between=True)
    with Tree(other.process):
        check(other.ends(10) == 1,
              "limbo-launchd does not start for one that isn't its parent")

    broker = StandInBroker(limbo, table, outdir)
    with Tree(broker.process) as process:
        broker.until("JOBS_LOADED")
        broker.sock.close()
        status = broker.ends()
        check(status != 0,
              f"limbo-launchd fails when the broker goes: {status}")

    sysroot = with_sleep()
    if not sysroot:
        NOT_RUN.append("limbo-launchd with jobs and a stand-in broker: jobs "
                       "stopped as the broker goes")
        return
    first = "com.limbo.test.launchd.first"
    table.write_text(job_table(sysroot, [(first, "runatload", first)]))

    broker = StandInBroker(limbo, table, outdir)
    with Tree(broker.process) as process:
        broker.until("JOBS_LOADED")
        job = (children(process.pid) or [None])[0]
        broker.sock.close()
        status = broker.ends()
        check(status != 0,
              f"limbo-launchd fails when the broker goes: {status}")
        check(job is not None and not running(job), "with its job stopped")


def main():
    limbo, broker, header, outdir = sys.argv[1:5]
    read_header(header)
    outdir = Path(outdir).resolve()
    ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)
    broker_and_launchd(broker, outdir)
    broker_and_stand_in(broker, outdir)
    launchd_and_stand_in(limbo, outdir)
    if NOT_RUN:
        print("the parts without jobs passed; NOT RUN, for want of a sysroot "
              "(LIMBO_SYSROOT) with bin/sleep:\n- " + "\n- ".join(NOT_RUN))
        raise SystemExit(77)
    print("ok")


if __name__ == "__main__":
    main()
