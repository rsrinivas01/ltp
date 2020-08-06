/*
 *
 *   Copyright (c) International Business Machines  Corp., 2002
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* 11/12/2002   Port to LTP     robbiew@us.ibm.com */
/* 06/30/2001	Port to Linux	nsharoff@us.ibm.com */

/*
 * NAME
 *	rename14.c - create and rename files
 *
 * CALLS
 *	create, unlink, rename
 *
 * ALGORITHM
 *	Creates two processes.  One creates and unlinks a file.
 *	The other renames that file.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "test.h"

char *TCID = "rename14";
int TST_TOTAL = 1;

int main(int argc, char *argv[])
{
	int fd;
	int ret = -1;

	tst_parse_opts(argc, argv, NULL, NULL);

	tst_tmpdir();
	
	fd = creat("./rename14", 0666);
	close(fd);
	
	ret = rename("./rename14", "./rename14xyz");

	if (ret == 0)
	{
		tst_resm(TPASS, "Test Passed");
	} 
	else
	{
		tst_resm(TFAIL, " Test Failed.. rename returned %d, errno = %d", ret, errno);
	}
	
	unlink("./rename14");
	unlink("./rename14xyz");
	
	tst_rmdir();
	tst_exit();

}
