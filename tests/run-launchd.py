#!/usr/bin/env python3

import ctypes
import os
import platform
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
NAME_HELD, NAME_UNLOADED = 0x1, 0x4
AWAITED_DEMANDED = 0x1
DOMAIN_USER, DOMAIN_SYSTEM = 0, 1
FRAME_OOL = 0x80000000

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


def launchctl(tool, env, *words, timeout=60):
    try:
        return subprocess.run([tool, *words], env=env, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        check(False, f"limbo-launchctl {' '.join(words)} is answered")


def job_table(sysroot, jobs):
    return "".join(f"{name} user - - - {flags} - - 0 {service} bin/sleep 600\n"
                   for name, flags, service in jobs) if sysroot else ""


def with_sleep():
    sysroot = os.environ.get("LIMBO_SYSROOT")
    return sysroot if sysroot and (Path(sysroot) / "bin/sleep").exists() else None


def broker_and_launchd(broker, tool, outdir):
    sysroot = with_sleep()
    if not sysroot:
        NOT_RUN.append("the real broker and limbo-launchd with jobs: a job "
                       "runs as limbo-launchd's child without its connection; "
                       "a system account with no user")
    table = outdir / "launchd-jobs.txt"
    agent = "com.limbo.test.launchd.agent"
    table.write_text(job_table(sysroot, [
        ("com.limbo.test.launchd.sleep", "runatload", "-"),
        ("account/" + agent, "-", agent)]))
    path = outdir / "launchd-broker.sock"
    env = dict(os.environ, LIMBO_JOB_LOGS=str(outdir), LIMBO_BROKER=str(path))

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

    def job_pid():
        for line in launchctl(tool, env, "list").stdout.splitlines():
            fields = line.split("\t")
            if (fields[-1] == "com.limbo.test.launchd.sleep"
                    and fields[2] == "running"):
                return int(fields[0])
        return None

    with Tree(start(str(table))) as process:
        listed = launchctl(tool, env, "list")
        check(listed.returncode == 0
              and listed.stdout.startswith("PID\tStatus\tState\tName\n"),
              f"limbo-launchctl list answers: {listed}")
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
        job = job_pid() if sysroot else None
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

        waiting = launchctl(tool, env, "waiting")
        check(waiting.returncode == 0 and waiting.stdout == "",
              f"limbo-launchctl waiting answers: {waiting}")
        unknown = launchctl(tool, env, "no-such-command")
        check(unknown.returncode == 1 and "unknown command" in unknown.stdout,
              f"an unknown command is refused: {unknown}")

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

        twice = connect(path)
        hello(twice, DOMAIN_USER, os.getuid())
        twice.send(frame("HELLO", struct.pack("II", DOMAIN_USER, os.getuid())))
        twice.send(frame("LOOKUP", name_field("com.limbo.test.launchd.none")
                         + struct.pack("III", DOMAIN_USER, 0, 0)))
        answer_of(twice, "LOOKUP_REPLY", "a hello said twice",
                  unwanted=("WELCOME",))
        twice.close()

        if sysroot:
            no_user(path, agent, sysroot)

        process.kill()
        process.wait()
        check(job is None or gone(job), "the job stopped with the broker")

    with Tree(start()) as process:
        waiting = launchctl(tool, env, "waiting")
        check(waiting.returncode == 0 and waiting.stdout == "",
              f"with no table, limbo-launchctl waiting answers: {waiting}")
        listed = launchctl(tool, env, "list")
        check(listed.returncode == 0
              and listed.stdout == "PID\tStatus\tState\tName\n",
              f"and list, with no jobs: {listed}")


def look_up(sock, name):
    sock.send(frame("LOOKUP", name_field(name) + struct.pack(
        "I", DOMAIN_USER)))
    found, hidden, port = struct.unpack("IIQ", answer_of(
        sock, "LOOKUP_REPLY", f"a look-up of {name}")[:16])
    return port if found else None


def no_user_uid(sysroot):
    taken = set()
    try:
        passwd = (Path(sysroot) / "private/etc/passwd").read_text(
            errors="replace")
    except OSError:
        passwd = ""
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[2].isdigit():
            taken.add(int(fields[2]))
    return next((uid for uid in range(499, 0, -1) if uid not in taken), None)


def no_user(path, agent, sysroot):
    uid = no_user_uid(sysroot)
    if uid is None:
        NOT_RUN.append("a system account with no user: the sysroot's "
                       "passwd has every one")
        return
    daemon = connect(path)
    guest_id = hello(daemon, DOMAIN_SYSTEM, 0)[0]
    port = (guest_id << 32) | 7
    daemon.send(frame("REGISTER", struct.pack("Q", port) + name_field(agent)
                      + struct.pack("I", 0)))
    registered = answer_of(daemon, "REGISTERED",
                           "the other domain's daemon checks in")
    port = struct.unpack("IIQQ", registered[:24])[3]
    asker = connect(path)
    hello(asker, DOMAIN_USER, uid)
    held = look_up(asker, agent)
    check(held is not None, f"{agent} is held")
    asker.send(frame("SEND", struct.pack("QI", held, 4) + bytes(12) + b"ping"))
    answer = answer_of(daemon, "DELIVER", f"uid {uid}'s send to {agent}")
    check(struct.unpack("Q", answer[:8]) == (port,),
          f"the other domain's daemon has it: {answer}")
    asker.close()
    daemon.close()


STAND_IN = r'''#!/usr/bin/env python3
import os, re, select, signal, socket, struct, sys, time
mode = os.environ["LIMBO_TEST_STAND_IN"]
N = {word.split("=")[0]: int(word.split("=")[1])
     for word in os.environ["LIMBO_TEST_NUMBERS"].split()}
sock = socket.socket(fileno=int(sys.argv[1]))
control = socket.socket(fileno=int(sys.argv[2]))
def send(kind, payload=b""):
    sock.send(struct.pack("II", kind, len(payload)) + payload)
def lost_payload(kind):
    memory = os.memfd_create("payload")
    os.write(memory, bytes(100000))
    socket.send_fds(sock, [struct.pack("II", kind, 100000)], [memory])
    os.close(memory)
def record(name, flags):
    send(N["NAME"], struct.pack("II", flags, 0) + name.encode().ljust(128, b"\0"))
if mode == "never":
    time.sleep(600)
if mode == "slow":
    for i in range(3):
        record(f"com.limbo.test.slow{i}", 0x1)
        time.sleep(N["DEADLINE_MS"] * 0.4 / 1000)
send(N["JOBS_LOADED"])
if mode == "lost":
    lost_payload(N["NAME"] | N["OOL"])
    record("com.limbo.test.lost", 0x1)
waiters = {}
while True:
    ready = select.select([sock, control], [], [])[0]
    if control in ready:
        asker = control.accept()[0]
        word = asker.recv(1 << 20)[8:].split(b"\0")[0].decode()
        def answer(text, status=0):
            reply = struct.pack("I", status) + text.encode()
            asker.send(struct.pack("II", N["CONTROL_REPLY"], len(reply))
                       + reply)
        if word == "waiting":
            answer("".join(f"{n}\t{name}\n"
                           for name, n in waiters.items() if n))
        else:
            answer("stand-in\n")
        asker.close()
    if sock not in ready:
        continue
    data = sock.recv(1 << 20)
    if len(data) < 8:
        break
    kind, length = struct.unpack("II", data[:8])
    body = data[8:8 + length]
    if kind == N["NAME_AWAITED"]:
        domain, flags, count = struct.unpack("III", body[:12])
        name = body[12:12 + 128].split(b"\0")[0].decode()
        waiters[name] = count
'''


def broker_and_stand_in(broker, tool, outdir):
    folder = outdir / "launchd-stand-in"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir()
    shutil.copy(broker, folder / "limbo-broker")
    (folder / "limbo").write_text(STAND_IN)
    (folder / "limbo").chmod(0o755)
    table = folder / "jobs.txt"
    table.write_text("")
    path = folder / "broker.sock"
    numbers = " ".join(f"{name}={FRAMES[name]}" for name in (
        "NAME", "JOBS_LOADED", "NAME_AWAITED", "CONTROL_REPLY"))
    numbers += (f" OOL={FRAME_OOL}"
                f" DEADLINE_MS={int(DEFINES['DEADLINE'] * 1000)}")

    def start(mode):
        if path.exists():
            path.unlink()
        env = dict(os.environ, LIMBO_TEST_STAND_IN=mode,
                   LIMBO_TEST_NUMBERS=numbers, LIMBO_BROKER=str(path))
        return subprocess.Popen([folder / "limbo-broker", str(path),
                                 "/dev/null", str(table)], env=env,
                                stderr=subprocess.PIPE, text=True), env, \
            time.monotonic()

    def listening(process):
        for _ in range(200):
            if process.poll() is not None:
                break
            try:
                connect(path).close()
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.05)

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

    process, env, started = start("slow")
    with Tree(process):
        listening(process)
        answer = launchctl(tool, env, "list")
        check(answer.returncode == 0 and answer.stdout == "stand-in\n",
              f"a limbo-launchd that loads slowly is waited for: {answer}, "
              f"{time.monotonic() - started:.1f} s")
        check(time.monotonic() - started > DEFINES["DEADLINE"],
              "for longer than the broker waits for one that says nothing")

    process, env, started = start("lost")
    with Tree(process):
        listening(process)
        launchctl(tool, env, "list")
        asker = connect(path)
        check(look_up(asker, "com.limbo.test.lost") is not None,
              "limbo-launchd's connection outlives a lost frame")
        asker.close()
        check(process.poll() is None, "and the broker goes on")


class StandInBroker:

    def __init__(self, limbo, table, outdir, between=False, small=False,
                 log=None):
        self.sock, theirs = socket.socketpair(socket.AF_UNIX,
                                              socket.SOCK_SEQPACKET)
        if small:
            self.room = theirs.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            theirs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1)
            self.theirs = theirs.dup()
        self.control_path = outdir / "launchd-stand-in-broker.launchd"
        if self.control_path.exists():
            self.control_path.unlink()
        control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        control.bind(str(self.control_path))
        control.listen()
        env = dict(os.environ, LIMBO_JOB_LOGS=str(outdir))
        command = ["limbo-launchd", str(theirs.fileno()),
                   str(control.fileno() if not between else -1), str(table)]
        self.log = log
        stderr = open(log, "w") if log else None
        if between:
            self.process = subprocess.Popen(
                [sys.executable, "-c",
                 "import subprocess, sys; sys.exit(subprocess.call("
                 "sys.argv[2:], executable=sys.argv[1], "
                 "pass_fds=[int(sys.argv[3])]))", limbo, *command],
                env=env, pass_fds=[theirs.fileno()])
        else:
            self.process = subprocess.Popen(command, executable=limbo, env=env,
                                            pass_fds=[theirs.fileno(),
                                                      control.fileno()],
                                            stderr=stderr)
        if stderr:
            stderr.close()
        theirs.close()
        control.close()
        self.names = {}
        self.backlog = []

    def until(self, kind, loaded=None, timeout=10.0):
        for at, got in enumerate(self.backlog):
            if got[0] == FRAMES[kind]:
                del self.backlog[at]
                return got[1]
        while True:
            got = receive(self.sock, timeout)
            if got is None:
                check(False, f"limbo-launchd sends a {kind} frame")
            if got[0] == FRAMES["NAME"]:
                flags, count = struct.unpack("II", got[1][:8])
                name = got[1][8:8 + NAME_MAX].split(b"\0")[0].decode()
                self.names[name] = (flags, struct.unpack(
                    f"{count}I", got[1][8 + NAME_MAX:8 + NAME_MAX + 4 * count]))
                if name == loaded and count != 0:
                    return None
                continue
            if got[0] == FRAMES[kind]:
                return got[1]
            self.backlog.append(got)

    def tell(self, kind, payload):
        self.sock.send(frame(kind, payload))

    def ask(self, *words):
        asker = connect(self.control_path)
        asker.send(frame("CONTROL", b"".join(word.encode() + b"\0"
                                             for word in words)))
        answer = answer_of(asker, "CONTROL_REPLY", f"{words[0]}")
        asker.close()
        return struct.unpack("I", answer[:4])[0], answer[4:].decode()

    def job(self, name):
        for line in self.ask("list")[1].splitlines():
            fields = line.split("\t")
            if fields[-1] == name and fields[2] == "running":
                return int(fields[0])
        return None

    def ends(self, timeout=None):
        try:
            return self.process.wait(timeout=timeout or DEFINES["DEADLINE"])
        except subprocess.TimeoutExpired:
            check(False, "limbo-launchd goes")

    def said(self):
        return Path(self.log).read_text() if self.log else ""


SENDS = {"aarch64": (206, 211), "x86_64": (44, 46)}.get(platform.machine(), ())


def waits_to_send(pid):
    try:
        words = Path(f"/proc/{pid}/syscall").read_text().split()
    except OSError:
        return False
    fields = stat_fields(pid)
    return (bool(words) and words[0].isdigit() and int(words[0]) in SENDS
            and fields is not None and fields[0] == "S")


def exits(limbo, table, outdir, name):
    log = outdir / "launchd-exits.log"
    broker = StandInBroker(limbo, table, outdir, log=log)

    def awaited(waiters, flags=0):
        broker.tell("NAME_AWAITED", struct.pack(
            "III", DOMAIN_USER, flags, waiters) + name_field(name))

    def state():
        for line in broker.ask("list")[1].splitlines():
            fields = line.split("\t")
            if fields[-1] == name:
                return fields[2], fields[0]

    def runs():
        return re.search(r"runs: (\d+)",
                         broker.ask("print", name)[1]).group(1)

    def goes(pid):
        os.kill(pid, signal.SIGKILL)
        said = broker.until("PROCESS_EXITED")
        check(struct.unpack("i", said[:4])[0] == pid,
              f"limbo-launchd tells the broker that pid {pid} exited")

    def read(pid):
        broker.tell("PROCESS_EXITED", struct.pack("i", pid))

    with Tree(broker.process):
        broker.until("JOBS_LOADED")
        job = broker.job(name)
        awaited(1)
        goes(job)
        check(state() == ("running", str(job)),
              f"its exit is not taken before the broker has read what it "
              f"sent: {state()}")
        awaited(0)
        read(job)
        check(state()[0] == "idle",
              f"a job no one waits for is not started again: {state()}")
        check(runs() == "1", "it ran once")
        awaited(1, AWAITED_DEMANDED)
        second = broker.job(name)
        check(second not in (None, job), "a job a guest sends to starts")
        goes(second)
        check(state() == ("running", str(second)), "its exit waits again")
        read(second)
        third = broker.job(name)
        check(third not in (None, job, second),
              f"a job a guest still waits for is started again: {state()}")
        check(runs() == "3", "it ran three times")
        awaited(0)
        goes(third)
        went = time.monotonic()
        while (state()[0] == "running"
               and time.monotonic() < went + 2 * DEFINES["STOP"] + 5):
            time.sleep(0.1)
        waited = time.monotonic() - went
        check(state()[0] == "idle"
              and "the broker has not said" in broker.said(),
              f"an exit the broker says nothing of is taken: {state()}, "
              f"{waited:.1f} s")
        check(waited > DEFINES["STOP"] - 0.5, f"in its time: {waited:.1f} s")
        awaited(1, AWAITED_DEMANDED)
        fourth = broker.job(name)
        check(fourth not in (None, job, second, third), "it starts again")
        goes(fourth)


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
        NOT_RUN.append("limbo-launchd with jobs and a stand-in broker: told "
                       "before it forks; a job's exit "
                       "and the broker's word; jobs stopped as the broker "
                       "goes")
        return
    first = "com.limbo.test.launchd.first"
    table.write_text(job_table(sysroot, [(first, "runatload", first)] + [
        (f"com.limbo.test.launchd.other{i}", "-",
         f"com.limbo.test.launchd.other{i}") for i in range(200)]))

    broker = StandInBroker(limbo, table, outdir, small=True)
    with Tree(broker.process) as process:
        broker.until("JOBS_LOADED", loaded=first)
        flags, domains = broker.names.get(first, (0, ()))
        check(flags & NAME_HELD and not flags & NAME_UNLOADED
              and DOMAIN_USER in domains,
              f"it told of the job's name, held and loaded: {flags:#x} {domains}")
        for _ in range(200):
            if waits_to_send(process.pid):
                break
            time.sleep(0.05)
        check(waits_to_send(process.pid),
              "limbo-launchd waits to send what it has to say")
        check(process.poll() is None and children(process.pid) == [],
              "limbo-launchd forks no job before it has told of the names")
        broker.theirs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                 broker.room // 2)
        broker.theirs.close()
        broker.until("JOBS_LOADED")
        check(broker.job(first) in children(process.pid), "and then started it")

    exits(limbo, table, outdir, first)

    broker = StandInBroker(limbo, table, outdir)
    with Tree(broker.process) as process:
        broker.until("JOBS_LOADED")
        job = broker.job(first)
        broker.sock.close()
        status = broker.ends()
        check(status != 0,
              f"limbo-launchd fails when the broker goes: {status}")
        check(job is not None and not running(job), "with its job stopped")


def main():
    limbo, broker, tool, header, outdir = sys.argv[1:6]
    read_header(header)
    outdir = Path(outdir).resolve()
    ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)
    broker_and_launchd(broker, tool, outdir)
    broker_and_stand_in(broker, tool, outdir)
    launchd_and_stand_in(limbo, outdir)
    if NOT_RUN:
        print("the parts without jobs passed; NOT RUN, for want of a sysroot "
              "(LIMBO_SYSROOT) with bin/sleep:\n- " + "\n- ".join(NOT_RUN))
        raise SystemExit(77)
    print("ok")


if __name__ == "__main__":
    main()
