/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <uchar.h>

#if !HAVE_CHAR32_T
#define char32_t uint32_t
#endif

#if !HAVE_CHAR16_T
#define char16_t uint16_t
#endif

#ifndef __GLIBC__
typedef int (*comparison_fn_t)(const void *, const void *);
#endif

#ifndef __COMPAR_FN_T
#define __COMPAR_FN_T
typedef int (*__compar_fn_t)(const void *, const void *);
#endif

#ifndef FTW_ACTIONRETVAL
#define FTW_ACTIONRETVAL 16
#endif

#ifndef FTW_CONTINUE
#define FTW_CONTINUE 0
#endif

#ifndef FTW_STOP
#define FTW_STOP 1
#endif

#ifndef FTW_SKIP_SUBTREE
#define FTW_SKIP_SUBTREE 2
#endif

#ifndef FTW_SKIP_SIBLINGS
#define FTW_SKIP_SIBLINGS 3
#endif
