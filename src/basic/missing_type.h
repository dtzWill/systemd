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
