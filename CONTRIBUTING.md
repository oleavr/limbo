# Contributing to Limbo

To have your code considered for inclusion, send a pull request.

To discuss the development of Limbo, visit [#limbo](https://webirc.oftc.net:8443/?channels=limbo)
on [irc.oftc.net](https://www.oftc.net/).

## Commit Messages

This codebases follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
Due to the nature of Limbo, there are no stability guarantees so stating breaking
changes is not necessary.

## Code Style

Limbo code is provided with a `.clang-format` and `.editorconfig` file. The
codebase is formatted with `clang-format -i` such that any given patch must not
have any changes after running `clang-format`. The format is meant to match Drew
DeVault's [cstyle](https://git.sr.ht/~sircmpwn/cstyle) as closely as possible,
but due to limitations of `clang-format` it may not be 100% correct. In any case,
`clang-format` is the single source of truth.

All files must be named in `snake_case` unless they are executables, such as
`cache-lookup` or their associated man page: `cache-lookup.1`.

The order of definitions in a file should follow [cstyle](https://git.sr.ht/~sircmpwn/cstyle),
except for functions definitions which follow a newspaper article-like format.
The core of the file should be the first function definition and all the helper
subroutines should be placed after. In other terms, the order of functions should
loosely follow the flattened call graph of the first function definition.

## Development

Limbo needs a macOS userspace to run programs against. Bootstrap a sysroot as
described in the [User's Guide](README.md#Users-Guide) and export
`LIMBO_SYSROOT` to point at it.

Build Limbo:
```
meson setup build
ninja -C build
```

Then run a program with the `limbo` you just built by passing it the path to
the program, followed by the program's `argv`:
```
build/limbo $LIMBO_SYSROOT/bin/echo echo Hello, world
```

Programs spawned by that program are run by the *binfmt.d*(5) handler, so for
those to use your build, point `/etc/binfmt.d/Mach-O.conf` at it.

To see the system calls a program makes, name a directory in `LIMBO_TRACE` and
print what Limbo recorded there with `limbo-trace`:
```
mkdir /tmp/trace
LIMBO_TRACE=/tmp/trace build/limbo $LIMBO_SYSROOT/bin/echo echo Hello, world
build/limbo-trace /tmp/trace
```

`limbo-trace` names a system call by its row in `trace_names.h`, so a new
system call gets a row there.

## Testing

Run the test suite with `meson test -C build`. It consists of two suites:

* `unit` tests Limbo's own logic, such as path translation, and runs anywhere.
* `guest` compiles each program in `tests/guest` with the Xcode toolchain in
  `$LIMBO_SYSROOT` and runs it with the `limbo` that was just built. A guest
  test passes when its program exits with status 0. These tests register a
  private *binfmt.d*(5) handler in a user namespace, so that the programs they
  spawn also use the build under test. This requires unprivileged user
  namespaces and Linux 6.7 or later; the tests are skipped when that, or a
  sysroot with Xcode, is not available.

To add a guest test, write a C or C++ program in `tests/guest` that uses
`CHECK()` from `tests/check.h`, and list it in `tests/meson.build`.

CI runs both suites. It builds the sysroot with `etc/make-sysroot` on a macOS
runner and caches it until the runner's macOS or Xcode changes, or the script
does.

## Debugging

To debug Limbo, run your program under `gdbserver`:

```
gdbserver --no-startup-with-shell 127.0.0.1:1337 build/limbo \
	$LIMBO_SYSROOT/bin/echo echo Hello, world
```

Now you should be able to debug, but there a few other modifications that
make it a more pleasant experience. Add these to your `~/.gdbinit`:

```
set disassembly-flavor intel
set auto-load safe-path /a/path/limbo
set auto-load local-gdbinit on
```

This will automatically load the `.gdbinit` in the root of this repository which
will automatically connect to the `gdbserver` program and step over `SIGSYS`.
