/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

#include "time-util.h"
#include "util.h"

int unlink_noerrno(const char *path);

int rmdir_parents(const char *path, const char *stop);

int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

int readlinkat_malloc(int fd, const char *p, char **ret);
int readlink_malloc(const char *p, char **r);
int readlink_value(const char *p, char **ret);
int readlink_and_make_absolute(const char *p, char **r);

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);
int fchmod_and_chown(int fd, mode_t mode, uid_t uid, gid_t gid);

int fchmod_umask(int fd, mode_t mode);
int fchmod_opath(int fd, mode_t m);

int fd_warn_permissions(const char *path, int fd);

/*
   Avoid using AT_SYMLINK_NOFOLLOW flag. It doesn't seem like the right thing to
   do and it's not portable (not supported by musl). See:

     http://lists.landley.net/pipermail/toybox-landley.net/2014-September/003610.html
     http://www.openwall.com/lists/musl/2015/02/05/2

   Note that laccess() is never passing AT_EACCESS so a lot of the discussion in
   the links above doesn't apply. Note also that (currently) all systemd callers
   of laccess() pass mode as F_OK, so only check for existence of a file, not
   access permissions. Therefore, in this case, the only distiction between
   faccessat() with (flag == 0) and (flag == AT_SYMLINK_NOFOLLOW) is the
   behaviour for broken symlinks; laccess() on a broken symlink will succeed
   with (flag == AT_SYMLINK_NOFOLLOW) and fail (flag == 0).

   The laccess() macros was added to systemd some time ago and it's not clear if
   or why it needs to return success for broken symlinks. Maybe just historical
   and not actually necessary or desired behaviour?
*/

#define laccess(path, mode) faccessat(AT_FDCWD, (path), (mode), 0)

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode);
int touch(const char *path);

int symlink_idempotent(const char *from, const char *to);

int symlink_atomic(const char *from, const char *to);
int mknod_atomic(const char *path, mode_t mode, dev_t dev);
int mkfifo_atomic(const char *path, mode_t mode);

int get_files_in_directory(const char *path, char ***list);

int tmp_dir(const char **ret);
int var_tmp_dir(const char **ret);

int unlink_or_warn(const char *filename);

#define INOTIFY_EVENT_MAX (sizeof(struct inotify_event) + NAME_MAX + 1)

#define FOREACH_INOTIFY_EVENT(e, buffer, sz) \
        for ((e) = &buffer.ev;                                \
             (uint8_t*) (e) < (uint8_t*) (buffer.raw) + (sz); \
             (e) = (struct inotify_event*) ((uint8_t*) (e) + sizeof(struct inotify_event) + (e)->len))

union inotify_event_buffer {
        struct inotify_event ev;
        uint8_t raw[INOTIFY_EVENT_MAX];
};

int inotify_add_watch_fd(int fd, int what, uint32_t mask);

enum {
        CHASE_PREFIX_ROOT = 1 << 0, /* If set, the specified path will be prefixed by the specified root before beginning the iteration */
        CHASE_NONEXISTENT = 1 << 1, /* If set, it's OK if the path doesn't actually exist. */
        CHASE_NO_AUTOFS   = 1 << 2, /* If set, return -EREMOTE if autofs mount point found */
        CHASE_SAFE        = 1 << 3, /* If set, return EPERM if we ever traverse from unprivileged to privileged files or directories */
        CHASE_OPEN        = 1 << 4, /* If set, return an O_PATH object to the final component */
        CHASE_TRAIL_SLASH = 1 << 5, /* If set, any trailing slash will be preserved */
        CHASE_STEP        = 1 << 6, /* If set, just execute a single step of the normalization */
};

/* How many iterations to execute before returning -ELOOP */
#define CHASE_SYMLINKS_MAX 32

int chase_symlinks(const char *path_with_prefix, const char *root, unsigned flags, char **ret);

int chase_symlinks_and_open(const char *path, const char *root, unsigned chase_flags, int open_flags, char **ret_path);
int chase_symlinks_and_opendir(const char *path, const char *root, unsigned chase_flags, char **ret_path, DIR **ret_dir);
int chase_symlinks_and_stat(const char *path, const char *root, unsigned chase_flags, char **ret_path, struct stat *ret_stat);

/* Useful for usage with _cleanup_(), removes a directory and frees the pointer */
static inline void rmdir_and_free(char *p) {
        PROTECT_ERRNO;
        (void) rmdir(p);
        free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, rmdir_and_free);

static inline void unlink_and_free(char *p) {
        (void) unlink_noerrno(p);
        free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(char*, unlink_and_free);

int access_fd(int fd, int mode);

void unlink_tempfilep(char (*p)[]);
int unlinkat_deallocate(int fd, const char *name, int flags);

int fsync_directory_of_file(int fd);
