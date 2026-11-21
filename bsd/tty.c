/*
 * Copyright © 2026 Håvard Sørbø
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "bsd/tty.h"
#include "bsd/xnu-errno.h"

#define TIOCGETA    0x40487413
#define TIOCSETA    0x80487414
#define TIOCSETAW   0x80487415
#define TIOCSETAF   0x80487416
#define TIOCGWINSZ_ 0x40087468
#define TIOCSWINSZ_ 0x80087467
#define TIOCGPGRP_  0x40047477
#define TIOCSPGRP_  0x80047476
#define TIOCGSID_   0x40047463
#define TIOCSCTTY_  0x20007461
#define TIOCNOTTY_  0x20007471
#define TIOCEXCL_   0x2000740d
#define TIOCNXCL_   0x2000740e
#define TIOCOUTQ_   0x40047473
#define TIOCSTI_    0x80017472
#define TIOCFLUSH   0x80047410
#define TIOCDRAIN   0x2000745e
#define TIOCSTART   0x2000746e
#define TIOCSTOP    0x2000746f
#define TIOCGETD_   0x4004741a
#define TIOCSETD_   0x8004741b
#define TIOCPTYUNLK 0x20007452
#define TIOCPTYGNAME 0x40807453
#define TIOCPTYGRANT 0x20007454

#define FIOCLEX_   0x20006601
#define FIONCLEX_  0x20006602
#define FIOASYNC_  0x8004667d
#define FIONBIO_   0x8004667e
#define FIONREAD_  0x4004667f
#define FIODTYPE   0x4004667a

#define D_TTY 3

#define DARWIN_NCCS 20
#define DARWIN_VDISABLE 0xff
#define DARWIN_PTY_NAME_SIZE 128

struct darwin_termios {
	uint64_t c_iflag;
	uint64_t c_oflag;
	uint64_t c_cflag;
	uint64_t c_lflag;
	uint8_t c_cc[DARWIN_NCCS];
	uint64_t c_ispeed;
	uint64_t c_ospeed;
};

_Static_assert(sizeof(struct darwin_termios) == 72, "termios");

struct flag {
	uint64_t darwin;
	tcflag_t host;
};

static const struct flag iflags[] = {
		{0x1, IGNBRK},
		{0x2, BRKINT},
		{0x4, IGNPAR},
		{0x8, PARMRK},
		{0x10, INPCK},
		{0x20, ISTRIP},
		{0x40, INLCR},
		{0x80, IGNCR},
		{0x100, ICRNL},
		{0x200, IXON},
		{0x400, IXOFF},
		{0x800, IXANY},
		{0x2000, IMAXBEL},
		{0x4000, IUTF8},
};

static const struct flag oflags[] = {
		{0x1, OPOST},
		{0x2, ONLCR},
		{0x4, XTABS},
		{0x10, OCRNL},
		{0x20, ONOCR},
		{0x40, ONLRET},
		{0x80, OFILL},
		{0x20000, OFDEL},
};

static const struct flag cflags[] = {
		{0x400, CSTOPB},
		{0x800, CREAD},
		{0x1000, PARENB},
		{0x2000, PARODD},
		{0x4000, HUPCL},
		{0x8000, CLOCAL},
		{0x30000, CRTSCTS},
};

static const struct flag lflags[] = {
		{0x1, ECHOKE},
		{0x2, ECHOE},
		{0x4, ECHOK},
		{0x8, ECHO},
		{0x10, ECHONL},
		{0x20, ECHOPRT},
		{0x40, ECHOCTL},
		{0x80, ISIG},
		{0x100, ICANON},
		{0x400, IEXTEN},
		{0x800, EXTPROC},
		{0x400000, TOSTOP},
		{0x800000, FLUSHO},
		{0x20000000, PENDIN},
		{0x80000000, NOFLSH},
};

static const int control_chars[][2] = {
		{0, VEOF},
		{1, VEOL},
		{2, VEOL2},
		{3, VERASE},
		{4, VWERASE},
		{5, VKILL},
		{6, VREPRINT},
		{8, VINTR},
		{9, VQUIT},
		{10, VSUSP},
		{12, VSTART},
		{13, VSTOP},
		{14, VLNEXT},
		{15, VDISCARD},
		{16, VMIN},
		{17, VTIME},
};

static const struct {
	speed_t host;
	uint64_t rate;
} speeds[] = {
		{B0, 0},
		{B50, 50},
		{B75, 75},
		{B110, 110},
		{B134, 134},
		{B150, 150},
		{B200, 200},
		{B300, 300},
		{B600, 600},
		{B1200, 1200},
		{B1800, 1800},
		{B2400, 2400},
		{B4800, 4800},
		{B9600, 9600},
		{B19200, 19200},
		{B38400, 38400},
		{B57600, 57600},
		{B115200, 115200},
		{B230400, 230400},
		{B460800, 460800},
		{B921600, 921600},
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static uint64_t
flags_to_darwin(tcflag_t host, const struct flag *table, size_t count)
{
	uint64_t result = 0;
	for (size_t i = 0; i < count; i++) {
		if ((host & table[i].host) == table[i].host) {
			result |= table[i].darwin;
		}
	}
	return result;
}

static tcflag_t
flags_from_darwin(uint64_t darwin, const struct flag *table, size_t count)
{
	tcflag_t result = 0;
	for (size_t i = 0; i < count; i++) {
		if ((darwin & table[i].darwin) == table[i].darwin) {
			result |= table[i].host;
		}
	}
	return result;
}

static uint64_t
speed_to_darwin(speed_t host)
{
	for (size_t i = 0; i < COUNT(speeds); i++) {
		if (speeds[i].host == host) {
			return speeds[i].rate;
		}
	}
	return 38400;
}

static speed_t
speed_from_darwin(uint64_t rate)
{
	for (size_t i = 0; i < COUNT(speeds); i++) {
		if (speeds[i].rate == rate) {
			return speeds[i].host;
		}
	}
	return B38400;
}

static void
termios_to_darwin(const struct termios *host, struct darwin_termios *darwin)
{
	memset(darwin, 0, sizeof(*darwin));
	darwin->c_iflag = flags_to_darwin(host->c_iflag, iflags, COUNT(iflags));
	darwin->c_oflag = flags_to_darwin(host->c_oflag, oflags, COUNT(oflags));
	darwin->c_cflag = flags_to_darwin(host->c_cflag, cflags, COUNT(cflags))
			| ((uint64_t)((host->c_cflag & CSIZE) >> 4) << 8);
	darwin->c_lflag = flags_to_darwin(host->c_lflag, lflags, COUNT(lflags));
	memset(darwin->c_cc, DARWIN_VDISABLE, sizeof(darwin->c_cc));
	for (size_t i = 0; i < COUNT(control_chars); i++) {
		int index = control_chars[i][1];
		cc_t c = host->c_cc[index];
		bool timing = index == VMIN || index == VTIME;
		darwin->c_cc[control_chars[i][0]]
				= (c == _POSIX_VDISABLE && !timing)
				? DARWIN_VDISABLE
				: c;
	}
	darwin->c_ispeed = speed_to_darwin(cfgetispeed(host));
	darwin->c_ospeed = speed_to_darwin(cfgetospeed(host));
}

static void
termios_from_darwin(const struct darwin_termios *darwin, struct termios *host)
{
	memset(host, 0, sizeof(*host));
	host->c_iflag = flags_from_darwin(darwin->c_iflag, iflags, COUNT(iflags));
	host->c_oflag = flags_from_darwin(darwin->c_oflag, oflags, COUNT(oflags));
	host->c_cflag = flags_from_darwin(darwin->c_cflag, cflags, COUNT(cflags))
			| (((darwin->c_cflag >> 8) & 3) << 4);
	host->c_lflag = flags_from_darwin(darwin->c_lflag, lflags, COUNT(lflags));
	for (size_t i = 0; i < COUNT(control_chars); i++) {
		int index = control_chars[i][1];
		uint8_t c = darwin->c_cc[control_chars[i][0]];
		bool timing = index == VMIN || index == VTIME;
		host->c_cc[index]
				= (c == DARWIN_VDISABLE && !timing) ? _POSIX_VDISABLE : c;
	}
	cfsetispeed(host, speed_from_darwin(darwin->c_ispeed));
	cfsetospeed(host, speed_from_darwin(darwin->c_ospeed));
}

static int
set_attributes(int fd, int action, const struct darwin_termios *darwin)
{
	struct termios host;
	termios_from_darwin(darwin, &host);
	return errno_map(tcsetattr(fd, action, &host));
}

int
tty_ioctl(int fd, uint64_t command, void *data)
{
	switch (command) {
	case FIODTYPE: {
		struct stat s;
		if (fstat(fd, &s) == -1) {
			return err_map(errno);
		}
		if (!S_ISCHR(s.st_mode)) {
			return _ENOTTY;
		}
		*(int *)data = isatty(fd) ? D_TTY : 0;
		return 0;
	}
	case FIONREAD_:
		return errno_map(ioctl(fd, FIONREAD, data));
	case FIONBIO_: {
		int flags = fcntl(fd, F_GETFL);
		if (flags == -1) {
			return err_map(errno);
		}
		flags = *(int *)data ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
		return errno_map(fcntl(fd, F_SETFL, flags));
	}
	case FIOASYNC_:
		return errno_map(ioctl(fd, FIOASYNC, data));
	case FIOCLEX_:
		return errno_map(fcntl(fd, F_SETFD, FD_CLOEXEC));
	case FIONCLEX_:
		return errno_map(fcntl(fd, F_SETFD, 0));
	case TIOCGETA: {
		struct termios host;
		if (tcgetattr(fd, &host) == -1) {
			return err_map(errno);
		}
		termios_to_darwin(&host, data);
		return 0;
	}
	case TIOCSETA:
		return set_attributes(fd, TCSANOW, data);
	case TIOCSETAW:
		return set_attributes(fd, TCSADRAIN, data);
	case TIOCSETAF:
		return set_attributes(fd, TCSAFLUSH, data);
	case TIOCGWINSZ_:
		return errno_map(ioctl(fd, TIOCGWINSZ, data));
	case TIOCSWINSZ_:
		return errno_map(ioctl(fd, TIOCSWINSZ, data));
	case TIOCGPGRP_:
		return errno_map(ioctl(fd, TIOCGPGRP, data));
	case TIOCSPGRP_:
		return errno_map(ioctl(fd, TIOCSPGRP, data));
	case TIOCGSID_:
		return errno_map(ioctl(fd, TIOCGSID, data));
	case TIOCSCTTY_:
		return errno_map(ioctl(fd, TIOCSCTTY, 0));
	case TIOCNOTTY_:
		return errno_map(ioctl(fd, TIOCNOTTY));
	case TIOCEXCL_:
		return errno_map(ioctl(fd, TIOCEXCL));
	case TIOCNXCL_:
		return errno_map(ioctl(fd, TIOCNXCL));
	case TIOCOUTQ_:
		return errno_map(ioctl(fd, TIOCOUTQ, data));
	case TIOCSTI_:
		return errno_map(ioctl(fd, TIOCSTI, data));
	case TIOCDRAIN:
		return errno_map(tcdrain(fd));
	case TIOCSTART:
		return errno_map(tcflow(fd, TCOON));
	case TIOCSTOP:
		return errno_map(tcflow(fd, TCOOFF));
	case TIOCFLUSH: {

		int which = *(int *)data & 3;
		int queue = (which == 1) ? TCIFLUSH
				: (which == 2)   ? TCOFLUSH
						 : TCIOFLUSH;
		return errno_map(tcflush(fd, queue));
	}
	case TIOCGETD_:
		if (!isatty(fd)) {
			return _ENOTTY;
		}
		*(int *)data = 0;
		return 0;
	case TIOCSETD_:
		return isatty(fd) ? 0 : _ENOTTY;
	case TIOCPTYGRANT:
		return errno_map(grantpt(fd));
	case TIOCPTYUNLK:
		return errno_map(unlockpt(fd));
	case TIOCPTYGNAME: {
		unsigned int number;
		if (ioctl(fd, TIOCGPTN, &number) != 0) {
			return err_map(errno);
		}
		snprintf(data, DARWIN_PTY_NAME_SIZE, "/dev/ttys%03u", number);
		return 0;
	}
	default:
		return 1;
	}
}
