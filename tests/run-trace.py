#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    runner, limbo, limbo_trace, source, outdir = sys.argv[1:6]
    trace = (Path(outdir) / "traced.d").resolve()
    shutil.rmtree(trace, ignore_errors=True)
    trace.mkdir()
    env = dict(os.environ, LIMBO_TRACE=str(trace))
    run = [sys.executable, runner, limbo, source, outdir]
    result = subprocess.run(run, env=env)
    if result.returncode != 0:
        sys.exit(result.returncode)

    def print_trace():
        printed = subprocess.run([limbo_trace, trace], capture_output=True,
                                 text=True, check=True).stdout
        return [line for line in printed.splitlines() if " traced[" in line]

    lines = print_trace()

    def find(pattern):
        for line in lines:
            match = re.search(pattern, line)
            if match is not None:
                return match
        print("\n".join(lines[-60:]), file=sys.stderr)
        print(f"run-trace: no line matches {pattern}", file=sys.stderr)
        sys.exit(1)

    started = r"\+\+\+ started by {}: \S*traced \S*traced{}( \(.*\))? \+\+\+$"
    parent = find(r" traced\[(\d+)\] " + started.format(r"\d+", "")).group(1)
    find(rf' traced\[{parent}\] open\("/no/such/file", 0, 0\) = -1 ENOENT ')
    find(rf" traced\[{parent}\] send 3405 to 0x[0-9a-f]+, reply 0x[0-9a-f]+, ")
    find(rf" traced\[{parent}\] task_info = 4$")
    find(rf" traced\[{parent}\] receive 3505 on 0x[0-9a-f]+, reply 0, ")
    forked = find(r" traced\[(\d+)\] " + started.format(parent, "")).group(1)
    find(rf" traced\[{parent}\] fork\(\) = {forked} ")
    find(rf" traced\[{forked}\] \.\.\. fork = {parent}$")
    find(rf" traced\[{forked}\] exit\(0x3\) \.\.\.$")
    spawned = find(r" traced\[(\d+)\] "
                   + started.format(parent, " spawned")).group(1)
    find(rf" traced\[{spawned}\] exit\(0x5\) \.\.\.$")
    find(rf" traced\[{parent}\] exit\(0\) \.\.\.$")

    subprocess.run([limbo_trace, "-s", "off", trace], check=True)
    subprocess.run(run, env=env, check=True)
    switched_off = print_trace()[len(lines):]
    if [" +++ started by " in line for line in switched_off] != [True] * 3:
        print("\n".join(switched_off[:60]), file=sys.stderr)
        print("run-trace: recorded while switched off", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
