#!/usr/bin/env python3

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

SKIP = 77

MAGICS = {
    "Mach-O 64-bit": r"\xcf\xfa\xed\xfe",
    "Fat Mach-O": r"\xca\xfe\xba\xbe",
}


def main():
    limbo, source, outdir = sys.argv[1:4]
    broker = sys.argv[4] if len(sys.argv) > 4 else None
    sysroot = os.environ.get("LIMBO_SYSROOT")
    if sysroot is None:
        skip("LIMBO_SYSROOT is not set")
    xcrun = Path(sysroot) / "usr" / "bin" / "xcrun"
    if not xcrun.exists():
        skip(f"{xcrun} does not exist")

    if os.environ.get("LIMBO_TEST_NAMESPACE") is None:
        enter_namespace()

    register_binfmt(Path(limbo).resolve(), Path(outdir) / "binfmt")
    drop_privileges()
    binary = compile_program(xcrun, Path(source), Path(outdir))
    broker_process = (start_broker(broker, Path(outdir) / f"{binary.name}.sock",
                                   binary, Path(outdir))
                      if broker else None)
    try:
        result = subprocess.run([binary], cwd=outdir, timeout=240)
    finally:
        if broker_process is not None:
            broker_process.terminate()
    sys.exit(result.returncode)


def start_broker(broker, socket_path, binary, outdir):
    if socket_path.exists():
        socket_path.unlink()
    held_names = socket_path.with_suffix(".held")
    held_names.write_text("com.limbo.test.ipc.held\ncom.limbo.test.ipc.idle\n"
                          "com.limbo.test.ipc.late\ncom.limbo.test.ipc.orphan\n"
                          "com.limbo.test.ipc.demand\n"
                          "com.limbo.test.ipc.hidden!\n"
                          "com.limbo.test.ipc.rehidden!\n"
                          "com.limbo.test.ipc.returned\n"
                          "com.limbo.test.ipc.unforged\n")
    jobs = outdir / f"{binary.stem}-jobs.txt"
    if binary.stem == "xpc_launchd":
        sysroot = Path(os.environ["LIMBO_SYSROOT"])
        plist = "private/tmp/limbo-test-jobevents.plist"
        (sysroot / plist).write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            '<key>Label</key><string>com.limbo.test.jobevents</string>'
            '<key>LaunchEvents</key><dict>'
            '<key>com.limbo.test.jobevents</key><dict>'
            '<key>limbo-job-event</key><dict>'
            '<key>key</key><string>job</string>'
            '</dict></dict></dict></dict></plist>\n')
        marker = outdir.resolve() / "xpc-job-event.txt"
        if marker.exists():
            marker.unlink()
        jobs.write_text(f"com.limbo.test.jobevents user {plist} com.limbo.test.jobevents "
                        f"- - - - 0 com.limbo.test.jobevents#com.limbo.test.jobevents "
                        f"{binary.resolve()} job-subscriber {marker}\n")
        os.environ["LIMBO_TEST_JOB_EVENT"] = str(marker)
    elif binary.stem != "ipc_broker":
        jobs.write_text("")
    else:
        awaited_marker = outdir.resolve() / "ipc-awaited-marker"
        hello_marker = outdir.resolve() / "ipc-hello-again-marker"
        for marker in (awaited_marker, hello_marker):
            if marker.exists():
                marker.unlink()
        header = (Path(__file__).resolve().parent.parent / "broker.h").read_text()
        types = header[header.index("enum broker_frame_type {"):]
        types = re.findall(r"\b(BROKER_[A-Z_]+),", types[:types.index("};")])
        name_frame = types.index("BROKER_NAME")
        hello_frame = types.index("BROKER_HELLO")
        program = binary.resolve()
        jobs.write_text(f"gui/com.limbo.test.ipc.demand user - - - runatload - - 0 "
                        f"com.limbo.test.ipc.demand {program} serve-demand\n"
                        f"loginwindow/com.limbo.test.ipc.prompt user - - - runatload "
                        f"- - 0 com.limbo.test.ipc.prompt {program} "
                        f"serve-demand com.limbo.test.ipc.prompt\n"
                        f"com.limbo.test.ipc.awaited user - - - - - - 0 "
                        f"com.limbo.test.ipc.awaited {program} "
                        f"serve-second {awaited_marker}\n"
                        f"com.limbo.test.ipc.forger user - - - - - - 0 "
                        f"com.limbo.test.ipc.forger {program} "
                        f"forge {name_frame}\n"
                        f"com.limbo.test.ipc.hello-again user - - - - - - 0 "
                        f"com.limbo.test.ipc.hello-again {program} "
                        f"hello-again {hello_marker} {hello_frame}\n")
    env = dict(os.environ, LIMBO_JOB_LOGS=str(outdir))
    process = subprocess.Popen([broker, str(socket_path), str(held_names),
                                str(jobs)], env=env)
    wait_for_broker(socket_path)
    os.environ["LIMBO_BROKER"] = str(socket_path)
    return process


def wait_for_broker(socket_path):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as probe:
            try:
                probe.connect(str(socket_path))
                return
            except OSError:
                time.sleep(0.01)
    sys.exit(f"{socket_path} accepted no connection")


def skip(reason):
    print(f"skipping: {reason}")
    sys.exit(SKIP)


def enter_namespace():
    env = dict(os.environ, LIMBO_TEST_NAMESPACE="1",
               LIMBO_TEST_UNPRIVILEGED="1")
    if os.environ.get("LIMBO_TEST_USER") is not None and os.geteuid() == 0:
        enter_namespace_as_root()
        return
    command = ["unshare", "--user", "--map-root-user", "--map-auto",
               "--mount", "--propagation", "private"]
    try:
        probe = subprocess.run(command + ["true"], capture_output=True)
    except FileNotFoundError:
        skip("unshare is not available")
    if probe.returncode != 0:
        env = dict(os.environ, LIMBO_TEST_USER=f"{os.getuid()}:{os.getgid()}")
        command = ["sudo", "-n", "--preserve-env"]
    result = subprocess.run(command + [sys.executable] + sys.argv, env=env)
    sys.exit(result.returncode)


def enter_namespace_as_root():
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
        os.write(ready_w, b"x")
        os.read(go_r, 1)
        os.environ["LIMBO_TEST_NAMESPACE"] = "1"
        return
    os.read(ready_r, 1)
    for kind in ("uid", "gid"):
        with open(f"/proc/{pid}/{kind}_map", "w") as f:
            f.write("0 0 65536\n")
    os.write(go_w, b"x")
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status))


def drop_privileges():
    user = os.environ.get("LIMBO_TEST_USER")
    if user is None:
        return
    uid, gid = (int(n) for n in user.split(":"))
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)


def register_binfmt(limbo, mountpoint):
    mountpoint.mkdir(exist_ok=True)
    result = subprocess.run(["mount", "-t", "binfmt_misc", "binfmt_misc",
                             mountpoint], capture_output=True, text=True)
    if result.returncode != 0:
        skip("binfmt_misc cannot be mounted in a user namespace: "
             + result.stderr.strip())

    register = mountpoint / "register"
    for name, magic in MAGICS.items():
        register.write_text(f":{name}:M::{magic}::{limbo}:FP\n")


def compile_program(xcrun, source, outdir):
    binary = outdir / source.stem
    inputs = [source, source.parent.parent / "check.h"]
    if binary.exists() and all(binary.stat().st_mtime >= path.stat().st_mtime
                               for path in inputs):
        return binary

    compiler = "clang++" if source.suffix == ".cpp" else "clang"
    flags = ["-std=c++23"] if source.suffix == ".cpp" else []
    command = [xcrun, compiler, *flags, "-Wall", "-Werror",
               "-I", source.parent.parent, "-o", binary, source,
               "-framework", "CoreFoundation"]
    result = subprocess.run(command, timeout=240)
    if result.returncode != 0:
        sys.exit(result.returncode)
    return binary


if __name__ == "__main__":
    main()
