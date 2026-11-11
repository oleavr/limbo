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
    result = subprocess.run([sys.executable, runner, limbo, source, outdir],
                            env=env)
    if result.returncode != 0:
        sys.exit(result.returncode)

    printed = subprocess.run([limbo_trace, trace], capture_output=True,
                             text=True, check=True).stdout
    lines = [line for line in printed.splitlines() if " traced[" in line]

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
    find(rf" traced\[{parent}\] task_info = 4$")
    forked = find(r" traced\[(\d+)\] " + started.format(parent, "")).group(1)
    find(rf" traced\[{parent}\] fork\(\) = {forked} ")
    find(rf" traced\[{forked}\] \.\.\. fork = {parent}$")
    find(rf" traced\[{forked}\] exit\(0x3\) \.\.\.$")
    spawned = find(r" traced\[(\d+)\] "
                   + started.format(parent, " spawned")).group(1)
    find(rf" traced\[{spawned}\] exit\(0x5\) \.\.\.$")
    find(rf" traced\[{parent}\] exit\(0\) \.\.\.$")


if __name__ == "__main__":
    main()
