limbo-trace(1)

# NAME

limbo-trace - Print what Limbo recorded of its programs

# SYNOPSIS

_limbo-trace_ [*-fr*] _path_...++
_limbo-trace_ *-s* on|off _path_...

# DESCRIPTION

When *LIMBO_TRACE* names a directory, *limbo*(1) records the system calls of
each program it runs in a file there. This tool prints the records of each
_path_, a file or a directory of them, in the order they were made:

```
3104.876438 ls[628] open("/etc", 0x100000, 0) = 3 <0.000004>
3104.876451 ls[628/631] stat64("/etc/motd", 0x16fdfe6a0) = -1 ENOENT <0.000039>
```

A line has the time on the monotonic clock, in seconds, and the program with
its process and, where it is not the first, its thread. Then follow the system
call, its result and how long it took. A call that failed shows the name of
XNU's error. A call ends in _..._ when it had not returned as the file was
read, and a line that starts with _..._ is the return of a call whose start
was no longer in the file. _send_ and _receive_ are Mach messages, with their
ID, port, reply port and size, and a name with a result alone is the routine
of a kernel object that served one. A line in _+++_ tells of a process that
started.

The files can be read while their programs run and after they have gone.
Each thread keeps its latest records and overwrites the oldest; the line of a
process's start tells how much was overwritten.

Recording is switched with *-s*, for the running program whose file is
_path_, or for every program of a directory and those yet to start there.
Switched off, a program keeps its file and records nothing.

# OPTIONS

*-f*
	Keep printing records as they are made. A call that has not returned
	when it is printed ends in _..._, and its return follows on a line of
	its own.

*-r*
	After a call, print the paths it named with what they resolved to on
	the host.

*-s* on|off
	Switch recording on or off instead of printing.

# SEE ALSO

*limbo*(1)

# AUTHORS

Maintained by Keegan Saunders <keegan@undefinedbehaviour.org>, who is assisted
by other open source contributors. For more information about Limbo development,
see https://github.com/ksaunders/limbo.
