/*************************************************************************************/
/*                                                                                   */
/* Copyright (C) 2008, Michael Kerrisk <mtk.manpages@gmail.com>,                     */
/* Copyright (C) 2008, Linux Foundation                                              */
/*                                                                                   */
/* This program is free software;  you can redistribute it and/or modify             */
/* it under the terms of the GNU General Public License as published by              */
/* the Free Software Foundation; either version 2 of the License, or                 */
/* (at your option) any later version.                                               */
/*                                                                                   */
/* This program is distributed in the hope that it will be useful,                   */
/* but WITHOUT ANY WARRANTY;  without even the implied warranty of                   */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See                         */
/* the GNU General Public License for more details.                                  */
/*                                                                                   */
/* You should have received a copy of the GNU General Public License                 */
/* along with this program;  if not, write to the Free Software                      */
/* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA           */
/*************************************************************************************/
/*                                                                                   */
/* File: utimnsat01.c                                                                */
/* Description: A command-line interface for testing the utimensat() system call.    */
/* Author: Michael Kerrisk <mtk.manpages@gmail.com>                                  */
/* History:                                                                          */
/*	17 Mar  2008  Initial creation,                                              */
/*	31 May  2008  Reworked for easier test automation,                           */
/*	2  June 2008  Renamed from t_utimensat.c to test_utimensat.c,                */
/*	05 June 2008  Submitted to LTP by Subrata Modak <subrata@linux.vnet.ibm.com> */
/*************************************************************************************/

#define _GNU_SOURCE
#define _ATFILE_SOURCE
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include "test.h"
#include "lapi/syscalls.h"

char *TCID = "utimensat01";
int TST_TOTAL = 0;

#define cleanup tst_exit

/* We use EXIT_FAILURE for an expected failure from utimensat()
   (e.g., EACCES and EPERM), and one of the following for unexpected
   failures (i.e., something broke in our test setup). */

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

#define EXIT_bad_usage 3
#define EXIT_failed_syscall 3

#define errExit(msg)    do { perror(msg); exit(EXIT_failed_syscall); \
                        } while (0)

#define UTIME_NOW      ((1l << 30) - 1l)
#define UTIME_OMIT     ((1l << 30) - 2l)

int setup(int file_flags, mode_t file_mode, char *pathname);
int reset_tsp ();

static inline int
utimensat_sc(int dirfd, const char *pathname,
	     const struct timespec times[2], int flags)
{
	return ltp_syscall(__NR_utimensat, dirfd, pathname, times, flags);
}

static void usageError(char *progName)
{
	fprintf(stderr, "Usage: %s pathname [atime-sec "
		"atime-nsec mtime-sec mtime-nsec]\n\n", progName);
	fprintf(stderr, "Permitted options are:\n");
	fprintf(stderr, "    [-d path] "
		"open a directory file descriptor"
		" (instead of using AT_FDCWD)\n");
	fprintf(stderr, "    -q        Quiet\n");
	fprintf(stderr, "    -w        Open directory file "
		"descriptor with O_RDWR|O_APPEND\n"
		"              (instead of O_RDONLY)\n");
	fprintf(stderr, "    -n        Use AT_SYMLINK_NOFOLLOW\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "pathname can be \"NULL\" to use NULL "
		"argument in call\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "Either nsec field can be\n");
	fprintf(stderr, "    'n' for UTIME_NOW\n");
	fprintf(stderr, "    'o' for UTIME_OMIT\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "If the time fields are omitted, "
		"then a NULL 'times' argument is used\n");
	fprintf(stderr, "\n");

	exit(EXIT_bad_usage);
}

/* Renamed existing main to new_main for processing arguments.
 * This is done to avoid making huge amount of changes to
 * existing main. Instead the old main() is renamed to new_main()
 * and minimal changes are done such as returning error or success
 * to the caller instead of exiting when there is a failure or success.
 * This function is called with argc and argv according to the test
 * scenario to be tested. So this function will just treat that argc
 * and argv are received from command line and try to parse using
 * getopt() and test the utimensat() success and error conditions.
 */

int new_main(int argc, char *argv[])
{
	int flags, dirfd, opt, oflag;
	struct timespec ts[2];
	struct timespec *tsp;
	char *pathname, *dirfdPath;
	struct stat sb;
	int verbose;

	/* Command-line argument parsing */
	
	flags = 0;
	verbose = 1;
	dirfd = AT_FDCWD;
	dirfdPath = NULL;
	oflag = O_RDONLY;

	while ((opt = getopt(argc, argv, "d:nqw")) != -1) {
		switch (opt) {
		case 'd':
			dirfdPath = optarg;
			break;

		case 'n':
			flags |= AT_SYMLINK_NOFOLLOW;
			if (verbose)
				printf("Not following symbolic links\n");
			break;

		case 'q':
			verbose = 0;
			break;

		case 'w':
			oflag = O_RDWR | O_APPEND;
			break;
		/* Added new case to print the invalid option character
		 * received in argv */
		case '?':
			printf  ("option character `\\x%x'.\n", optopt);
			break;
		default:
			usageError(argv[0]);
		}
	}

	if ((optind + 5 != argc) && (optind + 1 != argc))
		usageError(argv[0]);

	if (dirfdPath != NULL) {
		dirfd = open(dirfdPath, oflag);
		/* Ignoring open error to test EBADF scenario.
		 * open() is invoked during the test setup via
		 * the setup() function which is newly added.
		 * So the above open() is really not used.
		 * It is now used to pass invalid dirfd i.e
		 * EBADF test case. Non existing file is passed along
		 * with -d option so that open() will return -1
		 */
		if (dirfd == -1)
			printf("open error\n");

		if (verbose) {
			printf("Opened dirfd %d", oflag);
			if ((oflag & O_ACCMODE) == O_RDWR)
				printf(" O_RDWR");
			if (oflag & O_APPEND)
				printf(" O_APPEND");
			printf(": %s\n", dirfdPath);
		}
	}

	pathname = (strcmp(argv[optind], "NULL") == 0) ? NULL : argv[optind];

	/* Either, we get no values for 'times' fields, in which case
	   we give a NULL pointer to utimensat(), or we get four values,
	   for secs+nsecs for each of atime and mtime.  The special
	   values 'n' and 'o' can be used for tv_nsec settings of
	   UTIME_NOW and UTIME_OMIT, respectively. */

	if (argc == optind + 1) {
		tsp = NULL;

	} else {
		ts[0].tv_sec = atoi(argv[optind + 1]);
		if (argv[optind + 2][0] == 'n') {
			ts[0].tv_nsec = UTIME_NOW;
		} else if (argv[optind + 2][0] == 'o') {
			ts[0].tv_nsec = UTIME_OMIT;
		} else {
			ts[0].tv_nsec = atoi(argv[optind + 2]);
		}

		ts[1].tv_sec = atoi(argv[optind + 3]);
		if (argv[optind + 4][0] == 'n') {
			ts[1].tv_nsec = UTIME_NOW;
		} else if (argv[optind + 4][0] == 'o') {
			ts[1].tv_nsec = UTIME_OMIT;
		} else {
			ts[1].tv_nsec = atoi(argv[optind + 4]);
		}

		tsp = ts;
	}

	/* For testing purposes, it may have been useful to run this program
	   as set-user-ID-root so that a directory file descriptor could be
	   opened as root.  (This allows us to obtain a file descriptor even
	   if normal user doesn't have permissions on the file.)  Now we
	   reset to the real UID before making the utimensat() call, so that
	   the permission checking for the utimensat() call is performed
	   under that UID. */

	if (geteuid() == 0) {
		uid_t u;

		u = getuid();

		if (verbose)
			printf("Resetting UIDs to %ld\n", (long)u);

		if (setresuid(u, u, u) == -1)
			errExit("setresuid");
	}

	/* Display information allowing user to verify arguments for call */

	if (verbose) {
		printf("dirfd is %d\n", dirfd);
		printf("pathname is %s\n", pathname);
		printf("tsp is %p", tsp);
		if (tsp != NULL) {
			printf("; struct  = { %ld, %ld } { %ld, %ld }",
			       (long)tsp[0].tv_sec, (long)tsp[0].tv_nsec,
			       (long)tsp[1].tv_sec, (long)tsp[1].tv_nsec);
		}
		printf("\n");
		printf("flags is %d\n", flags);
	}

	/* Make the call and see what happened */
	/* In earlier implementation failure of utimensat_sc() is
	 * treated as a failure and the test is existed with exit().
	 * This doesn't give a chance to test the error case sceanrios
	 * for the utimensat(). Below changes are made to return with
	 * error number in case of utimensat() failure. The caller of this
	 * function i.e main() will validate and check if the error is
	 * expected or not based on the test case and pass or fail the
	 * test accordingly.
	 */

	if (utimensat_sc(dirfd, pathname, tsp, flags) == -1) {
		if (errno == EPERM) {
			if (verbose)
				printf("utimensat() returned with EPERM\n");
			else
				printf("EPERM\n");
			return EPERM;

		} else if (errno == EACCES) {
			if (verbose)
				printf("utimensat() returned with EACCES\n");
			else
				printf("EACCES\n");
			return EACCES;

		} else if (errno == EINVAL) {
			if (verbose)
				printf("utimensat() returned with EINVAL\n");
			else
				printf("EINVAL\n");
			return EINVAL;

		} else if (errno == EBADF) {
			if (verbose)
				printf("utimensat() returned with EBADF\n");
			else
				printf("EBADF\n");
			optind = 1;
			return EBADF;

		} else if (errno == ENAMETOOLONG) {
			if (verbose)
				printf("utimensat() returned with ENAMETOOLONG\n");
			else
				printf("ENAMETOOLONG\n");
			return ENAMETOOLONG;

		} else if (errno == ENOENT) {
			if (verbose)
				printf("utimensat() returned with ENOENT\n");
			else
				printf("ENOENT\n");
			return ENOENT;

		} else {	/* Unexpected failure case from utimensat() */
			errExit("utimensat");
		}
	}

	if (verbose)
		printf("utimensat() succeeded\n");

	if (stat((pathname != NULL) ? pathname : dirfdPath, &sb) == -1)
		errExit("stat");

	if (verbose) {
		printf("Last file access:         %s", ctime(&sb.st_atime));
		printf("Last file modification:   %s", ctime(&sb.st_mtime));
		printf("Last status change:       %s", ctime(&sb.st_ctime));

	} else {
		printf("SUCCESS %ld %ld\n", (long)sb.st_atime,
		       (long)sb.st_mtime);
	}

	return 0;
}

/* Below data structures are different argv[] strcutures passed in
 * as parameters to the new_main() function from main() function.
 * The argv[] will be simialr to argv[] of a command line invocation
 * of the application.
 */

/* Test 1 - Time value of NULL */
/* Command line: ./utimensat01 ./utimesat01_testfile */
char *argv_ptr0[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    NULL
};

/* Test 2 - Time value of tv_nsec = UTIME_NOW */
/* Command line: ./utimensat01 ./utimesat01_testfile 0 n 0 n */
char *argv_ptr1[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    (char *) "0",
    (char *) "n",
    (char *) "0",
    (char *) "n",
    NULL
};

/* Test 3 - Time value of tv_nsec = UTIME_OMIT */
/* Command line: ./utimensat01 ./utimesat01_testfile 0 o 0 o */
char *argv_ptr2[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    (char *) "0",
    (char *) "o",
    (char *) "0",
    (char *) "o",
    NULL
};

/* Test 4 - Time value of tv_nsec = UTIME_OMIT and UTIME_NOW */
/* Command line: ./utimensat01 ./utimesat01_testfile 0 n 0 o */
char *argv_ptr3[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    (char *) "0",
    (char *) "n",
    (char *) "0",
    (char *) "o",
    NULL
};

/* Test 5 - Time value of tv_nsec = UTIME_NOW and UTIME_OMIT */
/* Command line: ./utimensat01 ./utimesat01_testfile 0 o 0 n */
char *argv_ptr4[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    (char *) "0",
    (char *) "o",
    (char *) "0",
    (char *) "n",
    NULL
};

/* Test 6 - Time values of 1, 1, 1, 1 for both tv_sec and tv_nsec */
/* Command line: ./utimensat01 ./utimesat01_testfile 1 1 1 1 */
char *argv_ptr5[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    (char *) "1",
    (char *) "1",
    (char *) "1",
    (char *) "1",
    NULL
};

/* Test 7 - EBADF: Invalid dirfd (Invalid file specified for -d option) */
/* Command line: ./utimensat01 -d ./dirfd_file ./utimesat01_testfile */
char *argv_ptr6[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "-d",
    (char *) "./dirfd_file",
    (char *) "./utimesat01_testfile",
    NULL
};

/* Test 8 - EINVAL: Invalid value in one or both of the tv_nsec fields. */
/* Command line: ./utimensat01 ./utimesat01_testfile 1 -1 1 -1 */
char *argv_ptr7[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./utimesat01_testfile",
    (char *) "1",
    (char *) "-1",
    (char *) "1",
    (char *) "-1",
    NULL
};

/* Test 9 - ENAMETOOLONG: pathname is too long (Long file name as argument */
/* Command line: ./utimensat01 ./abcdef...... */
char *argv_ptr8[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "./abcdefghijklmnopqrstuvwxaaaaaaaaaaaaaaaaaaaaaaaaaa \
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
                aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    NULL
};

/* Test 10 - ENOENT (utimensat()) A component of pathname does not refer
*  to an existing directory or file, or pathname is an empty string.
*/
/* Command line: ./utimensat01  (An empty string as file name) */
char *argv_ptr9[] = {
    (char *) "utimensat01",	/* Executable */
    (char *) "",
    NULL
};

/* Test arguments for each of test case 1 to 10 */
char **argv_ptr[] = {argv_ptr0, argv_ptr1, argv_ptr2, argv_ptr3, argv_ptr4, 
	             argv_ptr5, argv_ptr6, argv_ptr7, argv_ptr8, argv_ptr9};

/* Test arguments size for each of test case 1 to 10 */
int  argv_size[]  = {2, 6, 6, 6, 6, 6, 4, 6, 2, 2};


/* Expected test result for each of test case 1 to 10.
 * 0 - Expecting result is success i.e. 0 from new_main() function.
 * Other error numbers - Expected corresponding errorno.
 */
int  expected_result[] = {0, 0, 0, 0, 0, 0, EBADF, EINVAL, ENAMETOOLONG, ENOENT}; 

/* Newly added main() function to pass on relevant argc and argv to
 * new_main() based on the test case and check the pass or failure
 * of utimensat(). This is just a stub() function to use the above
 * argc and argv arrays and invoke new_main() for performing the test.
 *
 * It does the following.
 * 	- Invoke setup() function to create a test file.
 * 	- For each test case,
 * 		1. reset the time stamps of test file using reset_tsp() function.
 * 		2. invoke new_main() with proper argc and argv as per test case.
 * 		3. validate the return value of new_main() to check if the test is
 * 		   passed or failed.
 */

int main(int argc, char *argv[])
{
	int i;
	int ret = -1;

	ret = setup(O_CREAT | O_RDONLY, S_IRUSR, "./utimesat01_testfile");
	if (ret < 0)
	{
		tst_brkm(TCONF, NULL, "Failed to create test file");
	}

	/* Tests 1 to 10 */
	for (i = 0; i < 10; i++)
	{
		ret = reset_tsp ();

		if (ret < 0)
		{
			tst_brkm(TCONF, NULL, "File time stamp reset failed for Test %d", i+1);
			continue;
		}

		ret = new_main (argv_size[i], argv_ptr[i]);	
	
		tst_resm(TINFO, "Test-%d expected = %d received = %d ",	i+1, expected_result[i], ret);

		if (ret == expected_result[i])
		{
			tst_resm(TPASS, "Test-%d passed ", i+1);
		}
		else 
		{
			tst_resm(TFAIL, "Test-%d failed ", i+1);
		}
	}
}

/* Common setup for test case.
 * Creates the test file with required permissions.
 */

int setup(int file_flags, mode_t file_mode, char *pathname)
{
	int fd = open(pathname, file_flags, file_mode);

	if (fd == -1)
	{
		tst_brkm(TCONF, NULL, "File creation failed, errnor = %d\n", errno);
		return -1;
	}

	tst_resm (TINFO, "file flags is 0x%X",  file_flags);
	tst_resm (TINFO, "file mode is 0x%X", file_mode);

	return 0;

}

/* Reset timestamps for the test file.
 * Using the utimensat() itself this function will try to
 * reset the time stamps of test file (modifications and access times) i.e
 * to Jan 1, 1970 00:00:00
 */
int reset_tsp ()
{
	struct timespec ts[2];
	struct stat sb;
	char *pname = "./utimesat01_testfile";

	/* Reset times to 0 */        
	ts[0].tv_sec  = 0;
	ts[0].tv_nsec = 0;
	ts[1].tv_sec  = 0;
	ts[1].tv_nsec = 0;
	
	if (utimensat_sc(AT_FDCWD, pname, ts, AT_SYMLINK_NOFOLLOW) == -1)
	{
		tst_resm (TINFO, "utimensat failed, errno = %d \n", errno);
		return -1;
	}
	else
	{
		if (stat(pname, &sb) == -1)
			return -1;
		else
		{
			if (sb.st_atime == 0 && sb.st_mtime ==0)
			{
				return 0;
			}
		}
	}
	return -1;
}
