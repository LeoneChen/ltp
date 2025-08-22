/*
 * Copyright (C) 2015 Cyril Hrubis <chrubis@suse.cz>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <sys/syscall.h>

#include "test.h"
#include "safe_macros.h"
#include "lapi/futex.h"

#define DEFAULT_MSEC_TIMEOUT 10000

#define NO_FUTEX 2
#define SOCK_PATH_FMT "/tmp/gramine_checkpoint_%u.sock"

#if (NO_FUTEX == 1)
int *tst_socks = NULL;
unsigned int tst_max_socks = 0;
#else
futex_t *tst_futexes;
unsigned int tst_max_futexes;
#endif

void tst_checkpoint_init(const char *file, const int lineno,
                         void (*cleanup_fn)(void))
{
#if (NO_FUTEX == 1)
	struct sockaddr_un addr;
	int max_socks = 128;

	if (tst_socks) {
		tst_brkm_(file, lineno, TBROK, cleanup_fn,
			"checkpoints already initialized");
		return;
	}
#else
	int fd;
	unsigned int page_size;

	if (tst_futexes) {
		tst_brkm_(file, lineno, TBROK, cleanup_fn,
			"checkpoints already initialized");
		return;
	}
#endif

	/*
	 * The parent test process is responsible for creating the temporary
	 * directory and therefore must pass non-zero cleanup (to remove the
	 * directory if something went wrong).
	 *
	 * We cannot do this check unconditionally because if we need to init
	 * the checkpoint from a binary that was started by exec() the
	 * tst_tmpdir_created() will return false because the tmpdir was
	 * created by parent. In this case we expect the subprogram can call
	 * the init as a first function with NULL as cleanup function.
	 */
	if (cleanup_fn && !tst_tmpdir_created()) {
		tst_brkm_(file, lineno, TBROK, cleanup_fn,
			"You have to create test temporary directory "
			"first (call tst_tmpdir())");
		return;
	}

#if (NO_FUTEX == 1)
	tst_socks = SAFE_MALLOC(cleanup_fn, max_socks * sizeof(*tst_socks));
	for (int i = 0; i < max_socks; i++) {
		int listen_fd = SAFE_SOCKET(cleanup_fn, AF_UNIX, SOCK_STREAM, 0);

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path, sizeof(addr.sun_path), SOCK_PATH_FMT, i);
		unlink(addr.sun_path);

		SAFE_BIND(cleanup_fn, listen_fd, (struct sockaddr*)&addr, sizeof(addr));
		SAFE_LISTEN(cleanup_fn, listen_fd, 128);
		tst_socks[i] = listen_fd;
	}
	tst_max_socks = max_socks;
#else
	page_size = getpagesize();

	fd = SAFE_OPEN(cleanup_fn, "checkpoint_futex_base_file",
	               O_RDWR | O_CREAT, 0666);

	SAFE_FTRUNCATE(cleanup_fn, fd, page_size);

	tst_futexes = SAFE_MMAP(cleanup_fn, NULL, page_size,
	                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	tst_max_futexes = page_size / sizeof(uint32_t);

	SAFE_CLOSE(cleanup_fn, fd);
#endif
}

int tst_checkpoint_wait(unsigned int id, unsigned int msec_timeout)
{
#if (NO_FUTEX == 1)
	int listen_fd = tst_socks[id], conn_fd;
	char buf;
	struct timeval timeout;
	int ret;
	fd_set rfds;

	do{
		FD_ZERO(&rfds);
		FD_SET(listen_fd, &rfds);
		timeout.tv_sec = msec_timeout / 1000;
		timeout.tv_usec = (msec_timeout % 1000) * 1000;
		ret = select(listen_fd + 1, &rfds, NULL, NULL, &timeout);
	} while(ret == -1 && errno == EINTR);

	if (ret <= 0) {
		if (ret == 0) {
			errno = ETIMEDOUT;
		}
		return -1;
	}

	conn_fd = accept(listen_fd, NULL, NULL);
	if (conn_fd < 0) {
		return -1;
	}

	do {
		FD_ZERO(&rfds);
		FD_SET(conn_fd, &rfds);
		timeout.tv_sec = msec_timeout / 1000;
		timeout.tv_usec = (msec_timeout % 1000) * 1000;
		ret = select(conn_fd + 1, &rfds, NULL, NULL, &timeout);
	} while(ret == -1 && errno == EINTR);

	if (ret <= 0) {
		if (ret == 0) {
			errno = ETIMEDOUT;
		}
		goto err;
	}

	if (recv(conn_fd, &buf, 1, 0) != 1) {
		goto err;
	}
	close(conn_fd);
	return 0;
err:
	close(conn_fd);
	return -1;
#elif (NO_FUTEX == 2)
	unsigned int waited = 0;

	if (!tst_max_futexes)
		tst_brkm(TBROK, NULL, "Set test.needs_checkpoints = 1");

	if (id >= tst_max_futexes)
	{
		errno = EOVERFLOW;
		return -1;
	}

	while (tst_futexes[id] == 0)
	{
		usleep(1000);
		waited++;
		if (msec_timeout && waited >= msec_timeout)
		{
			errno = ETIMEDOUT;
			return -1;
		}
	}

	return 0;
#else
	struct timespec timeout;
	int ret;

	if (!tst_max_futexes)
		tst_brkm(TBROK, NULL, "Set test.needs_checkpoints = 1");

	if (id >= tst_max_futexes) {
		errno = EOVERFLOW;
		return -1;
	}

	timeout.tv_sec = msec_timeout/1000;
	timeout.tv_nsec = (msec_timeout%1000) * 1000000;

	do {
		ret = syscall(SYS_futex, &tst_futexes[id], FUTEX_WAIT,
			      tst_futexes[id], &timeout);
	} while (ret == -1 && errno == EINTR);

	return ret;
#endif
}

int tst_checkpoint_wake(unsigned int id, unsigned int nr_wake,
                        unsigned int msec_timeout)
{
#if (NO_FUTEX == 1)
	struct timeval timeout;
	struct sockaddr_un addr;
	char buf = 1;
	fd_set write_fds;
	int ret;
	int conn_fd;

	for (int i = 0; i < nr_wake; i++) {
		conn_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (conn_fd < 0) {
			return -1;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		snprintf(addr.sun_path, sizeof(addr.sun_path), SOCK_PATH_FMT, id);

		if (connect(conn_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
			goto err;
		}

		do {
			FD_ZERO(&write_fds);
			FD_SET(conn_fd, &write_fds);
			timeout.tv_sec = msec_timeout / 1000;
			timeout.tv_usec = (msec_timeout % 1000) * 1000;
			ret = select(conn_fd + 1, NULL, &write_fds, NULL, &timeout);
		} while(ret == -1 && errno == EINTR);

		if (ret <= 0) {
			if (ret == 0) {
				errno = ETIMEDOUT;
			}
			goto err;
		}

		if (send(conn_fd, &buf, 1, 0) != 1) {
			goto err;
		}
		close(conn_fd);
	}
	return 0;
err:
	close(conn_fd);
	return -1;
#elif (NO_FUTEX == 2)
	if (!tst_max_futexes)
		tst_brkm(TBROK, NULL, "Set test.needs_checkpoints = 1");

	if (id >= tst_max_futexes)
	{
		errno = EOVERFLOW;
		return -1;
	}

	tst_futexes[id] = 1;
	sleep(1);
	tst_futexes[id] = 0;

	return 0;
#else
	unsigned int msecs = 0, waked = 0;

	if (!tst_max_futexes)
		tst_brkm(TBROK, NULL, "Set test.needs_checkpoints = 1");

	if (id >= tst_max_futexes) {
		errno = EOVERFLOW;
		return -1;
	}

	for (;;) {
		waked += syscall(SYS_futex, &tst_futexes[id], FUTEX_WAKE,
				 INT_MAX, NULL);

		if (waked == nr_wake)
			break;

		usleep(1000);
		msecs++;

		if (msecs >= msec_timeout) {
			errno = ETIMEDOUT;
			return -1;
		}
	}

	return 0;
#endif
}

void tst_safe_checkpoint_wait(const char *file, const int lineno,
                              void (*cleanup_fn)(void), unsigned int id,
			      unsigned int msec_timeout)
{
	int ret;

	if (!msec_timeout)
		msec_timeout = DEFAULT_MSEC_TIMEOUT;

	ret = tst_checkpoint_wait(id, msec_timeout);

	if (ret) {
		tst_brkm_(file, lineno, TBROK | TERRNO, cleanup_fn,
			"tst_checkpoint_wait(%u, %i) failed", id,
			msec_timeout);
	}
}

void tst_safe_checkpoint_wake(const char *file, const int lineno,
                              void (*cleanup_fn)(void), unsigned int id,
                              unsigned int nr_wake)
{
	int ret = tst_checkpoint_wake(id, nr_wake, DEFAULT_MSEC_TIMEOUT);

	if (ret) {
		tst_brkm_(file, lineno, TBROK | TERRNO, cleanup_fn,
			"tst_checkpoint_wake(%u, %u, %i) failed", id, nr_wake,
			DEFAULT_MSEC_TIMEOUT);
	}
}
