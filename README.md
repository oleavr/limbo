# limbo

Limbo is an XNU emulator similar to qemu-user; it translates XNU system calls
into their Linux equivalent(s). It is capable of executing supported binaries
targeting macOS or iOS on Linux without modification.

Limbo is currently only supported on Linux 5.11 or later with the
`CONFIG_GENERIC_ENTRY` option enabled. This is required to capture system calls
made by the guest program.

Sufficiently advanced programs, such as Apple Clang, are capable of compiling
binaries which can also be run in Limbo.

## Installation

Before installing, read the BSD-2-Clause [license](LICENSE).

To install, ensure [Meson](https://mesonbuild.com/) is installed and run the
following commands:
```
meson build
ninja -C build install
```

This will install Limbo and the associated documentation, but you must install
the *binfmt.d*(5) handlers by copying `etc/binfmt.d/Mach-O.conf` to
`/etc/binfmt.d/Mach-O.conf`. For development, omit the `install` option and
review [CONTRIBUTING.md](CONTRIBUTING.md). The [Development](CONTRIBUTING.md#Development)
section describes how to set up a development environment. The [Internals](#Internals)
section of the README gives an overview of how Limbo works.

## User's Guide

Limbo relies on a userspace like macOS or iOS to operate, so a "sysroot"
directory must be populated, or "bootstrapped", before use. Point Limbo at it by
exporting `LIMBO_SYSROOT`, e.g. in your shell profile:
```
export LIMBO_SYSROOT=$HOME/macos
```

Guest programs see the sysroot overlaid on the host's filesystem: an absolute
path resolves inside the sysroot when it exists there, and falls through to the
host otherwise, so `/System/Library/dyld` comes from the sysroot while `/tmp`,
`/home` and `/dev` are the host's. New files are created inside the sysroot
when their parent directory exists only there. Symbolic links inside the
sysroot, including absolute ones, resolve within it.

Limbo targets the userspace of modern macOS (tested with macOS 27 and the
Xcode 26.6 toolchain). The x86_64 parts of it can be taken from any Mac, as most
utilities ship as Fat Mach-O binaries. Non-Fat Mach-O binaries are also
supported, but must match your architecture.

### From a Mac

`etc/make-sysroot` builds a sysroot with the Xcode toolchain from a Mac and
writes it as a tar archive to standard output, so it can be run over SSH:
```
mkdir -p $LIMBO_SYSROOT
ssh $MAC sh -s < etc/make-sysroot | tar -xp -C $LIMBO_SYSROOT
```

The Mac's Xcode must contain x86_64 code, and its license must have been
accepted; see [Xcode](#Xcode). The sections below describe how to assemble a
sysroot by hand.

### Minimalist

For simple binaries like `echo`, only the dyld cache and dyld itself are
required. Modern macOS splits the cache into a main file and several subcaches,
which all need to be copied. On an Intel Mac they live in
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld`; on an Apple Silicon
Mac the x86_64 cache is part of the Rosetta cryptex, in
`/System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld`. In the sysroot
they go directly in `/System/Library/dyld`. Intel Macs only ship the Haswell
cache, `dyld_shared_cache_x86_64h`, which Limbo uses when
`dyld_shared_cache_x86_64` is absent.

On the Limbo host:
```
mkdir -p $LIMBO_SYSROOT/System/Library/dyld $LIMBO_SYSROOT/bin \
	$LIMBO_SYSROOT/usr/lib $LIMBO_SYSROOT/usr/share
rsync -a "$MAC:/System/Volumes/Preboot/Cryptexes/Rosetta/System/Library/dyld/dyld_shared_cache_x86_64*" \
	$LIMBO_SYSROOT/System/Library/dyld/
rsync -a $MAC:/usr/lib/dyld "$MAC:/usr/lib/*.dylib" $LIMBO_SYSROOT/usr/lib/
rsync -a $MAC:/usr/share/firmlinks $LIMBO_SYSROOT/usr/share/
rsync -a $MAC:/bin/echo $LIMBO_SYSROOT/bin/
```

Then run the program on the Limbo host:
```
$LIMBO_SYSROOT/bin/echo Hello, world
```

Which should print "Hello, world".

### Xcode

The Xcode toolchain works, including `xcrun`, `clang`, `clang++` and `ld`.
Programs compiled and linked with it can then be run in Limbo.

First follow the [Minimalist](#Minimalist) guide, then copy the shell and the
`xcrun` and `xcode-select` shims:
```
mkdir -p $LIMBO_SYSROOT/usr/bin $LIMBO_SYSROOT/private/etc \
	$LIMBO_SYSROOT/private/var/db $LIMBO_SYSROOT/private/var/select \
	$LIMBO_SYSROOT/Library/Preferences
ln -s private/etc $LIMBO_SYSROOT/etc
ln -s private/var $LIMBO_SYSROOT/var
rsync -a $MAC:/bin/sh $MAC:/bin/bash $LIMBO_SYSROOT/bin/
rsync -a $MAC:/usr/bin/xcrun $MAC:/usr/bin/xcode-select $LIMBO_SYSROOT/usr/bin/
rsync -a $MAC:/private/var/select/sh $LIMBO_SYSROOT/private/var/select/
```

Copy `Xcode.app` into `$LIMBO_SYSROOT/Applications`. Note that Xcode installed on
an Apple Silicon Mac has had its x86_64 slices removed, so it is best extracted
from the universal `.xip`: its `Content` member is a pbzx-compressed cpio
archive. That archive stores the contents of hardlinked files only with the
first link, while the other links carry placeholder data, so the extractor must
not let those overwrite it.

Select it and accept its license:
```
ln -s /Applications/Xcode.app/Contents/Developer \
	$LIMBO_SYSROOT/private/var/db/xcode_select_link
$LIMBO_SYSROOT/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -license accept
```

Then, compile and run a C program:
```
echo 'int main() { return 0; }' > /tmp/example.c
$LIMBO_SYSROOT/usr/bin/xcrun clang /tmp/example.c -o /tmp/example
/tmp/example
```

## Internals

Limbo at its core is fundamentally simple, the complexity comes from the incongruity
between Linux and the XNU kernel.

When an application is spawned by the kernel and it detects Mach-O magic, it spawns
Limbo to "wrap" the executable by passing the path to the target program and its
original `argv[0]` as arguments to Limbo.

The first thing Limbo does is parse its own ELF header and enumerates the executable
segments to notify the kernel of the memory regions that are _allowed_ to perform
system calls using a Linux 5.11 feature known as Syscall User Dispatch. Any
system calls that occur outside of this region result in a `SIGSYS`. Limbo then
sets a `SIGSYS` handler as the entry point into the XNU emulation routine.

Next, Limbo maps the dyld shared cache and its subcaches at their preferred
address. The cache spans most of the top of the address space, where Linux
would otherwise place the stack, the vDSO and its mmap area, so Limbo first
re-executes itself with address space layout randomization disabled, which
moves all of those out of the way.

The cache's pointers must be rebased before use, which is too costly to do in
every process, so the first process to start prepares a copy of the cache in
`/private/var/db/limbo` inside the sysroot, keyed by the cache's UUID. The copy
is a reflink clone where possible, and holds the rebased pointers, which lets
processes share those pages instead of each writing their own. Darwin's
`libmalloc` and a few other libraries read the CPU number with `SIDT`, which
XNU allows but Linux turns into a slow emulated trap, so the prepared copy also
redirects each `SIDT` to a trampoline that reads the CPU number with `RDPID`.

Guest processes run with transparent huge pages disabled, as Darwin's
allocators reserve large regions and touch them sparsely.

Absolute paths passed to file system calls are resolved inside the sysroot
using `openat2(2)` with `RESOLVE_IN_ROOT`, which keeps symbolic links and `..`
from escaping it, and paths reported back to the guest have the sysroot prefix
stripped.

Limbo then parses the Mach-O file and reads the load commands to look for the
`LC_LOAD_DYLINKER` which specifies the program invoked by the kernel to link the
target application. Then, that program is mapped into memory, the stack is set
up, and Limbo executes the entry point of `dyld`.

Once `dyld` is started, it takes over the process and Limbo code is only entered
when a system call is made.

Threads created by the guest, including the workqueue threads that libdispatch
asks the kernel for, run on Linux threads managed by Limbo. Mach ports, messages
and kernel objects are emulated within the process, and kernel object requests
are served by MIG-generated servers.

The XNU kernel is a hybrid kernel with a BSD and Mach subsystem, which is reflected
in Limbo's structure: `bsd`, `osfmk` (Mach) and `mdep` (Machine-dependent). When
Limbo is interrupted, it determines the subsystem of the syscall and dispatches
it into its appropriate handler, the subsystem then determines which syscall was
executed and dispatches it again where it is handled.

---

Special thanks to [David Weinstein](https://twitter.com/insitusec) for suggesting
the name Limbo.
