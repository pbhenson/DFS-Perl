/* Copyright (C) 1996 Transarc Corporation - All rights reserved. */
/* $Header: /afs/tr/project/dce/rcs/file/osi/RCS/osi_dir.h,v 1.2 1996/11/30 01:02:09 ota Exp $ */

/* Pick up the corrent definition of a dirent. */


#ifndef TRANSARC_OSI_DIR_H
#define TRANSARC_OSI_DIR_H

#if defined(AFS_SUNOS5_ENV) || defined(AFS_HPUX_ENV)
#include <sys/dirent.h>
#elif defined(AFS_AIX_ENV)
#include <sys/dir.h>
#elif defined(AFS_WINNT_ENV)

#define _D_NAME_MAX 255
#define OSI_MAXNAMLEN _D_NAME_MAX

struct dirent {
    /* POSIX defines d_offset but we don't use it. */
    ino_t d_ino;			/* "inode number" of entry */
    off_t d_off;			/* offset of disk directory entry */
    unsigned short d_reclen;		/* length of this record */
    unsigned short d_namlen;		/* length of string in d_name */
    char d_name[_D_NAME_MAX];		/* name of file */
};

#else
#error Dont know how to get dirent defined
#endif	/* !AFS_SUNOS5_ENV || AFS_HPUX_ENV */

#endif /* TRANSARC_OSI_DIR_H */
