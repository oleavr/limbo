limbo(1)

# NAME

limbo - XNU in Linux userspace

# SYNOPSIS

_limbo_ _path_ _argv0_ [_args_...]

This program is not meant to be executed directly. Instead, register binfmt handlers
for Mach-O programs.

# DESCRIPTION

Limbo is an XNU emulator similar to qemu-user; it translates XNU system calls
into their Linux equivalent(s). It is capable of executing supported binaries
targeting macOS or iOS on Linux without modification.

# OPTIONS

*path*
	Executes the specified file in Limbo.

*argv0*
	The name the program was invoked as, preserved by the binfmt.d(5) _P_
	flag.

*args*
	Arguments passed on to the program.

# ENVIRONMENT

*LIMBO_SYSROOT*
	Directory holding the macOS or iOS userspace. Absolute paths used by the
	program resolve inside it when they exist there, and on the host
	otherwise.

*LIMBO_TRACE*
	Directory to record the program's system calls in, a file for each
	process.

*LIMBO_TRACE_SIZE*
	Bytes of records that a thread keeps before it overwrites the oldest,
	rounded up to a power of two; 1048576 unless set.

# SEE ALSO

*cache-lookup*(1)

# AUTHORS

Maintained by Keegan Saunders <keegan@undefinedbehaviour.org>, who is assisted
by other open source contributors. For more information about Limbo development,
see https://github.com/ksaunders/limbo.
