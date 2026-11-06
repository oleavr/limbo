#!/usr/bin/env python3

import os
import subprocess
import sys
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
    broker_process = start_broker(broker, Path(outdir)) if broker else None
    try:
        result = subprocess.run([binary], cwd=outdir, timeout=240)
    finally:
        if broker_process is not None:
            broker_process.terminate()
    sys.exit(result.returncode)


def start_broker(broker, outdir):
    socket_path = outdir / "broker.sock"
    if socket_path.exists():
        socket_path.unlink()
    process = subprocess.Popen([broker, str(socket_path)])
    os.environ["LIMBO_BROKER"] = str(socket_path)
    return process


def skip(reason):
    print(f"skipping: {reason}")
    sys.exit(SKIP)


def enter_namespace():
    env = dict(os.environ, LIMBO_TEST_NAMESPACE="1")
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
