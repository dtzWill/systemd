/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdlib.h>

/* stdlib.h */
#if !HAVE_SECURE_GETENV
#  if HAVE___SECURE_GETENV
#    define secure_getenv __secure_getenv
#  else
#    error "neither secure_getenv nor __secure_getenv are available"
#  endif
#endif

/* string.h */
#if ! HAVE_STRNDUPA
#define strndupa(s, n) \
  ({ \
    const char *__old = (s); \
    size_t __len = strnlen(__old, (n)); \
    char *__new = (char *)alloca(__len + 1); \
    __new[__len] = '\0'; \
    (char *)memcpy(__new, __old, __len); \
  })
#endif
