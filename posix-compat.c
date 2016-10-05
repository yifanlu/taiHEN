/* posix-compat.c -- POSIX functions for libsubstitute to use
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
 #include <stdlib.h>

void *malloc(size_t size) {
  return NULL;
}

void free(void *ptr) {

}

void *realloc(void *ptr, size_t size) {
  return NULL;
}

void abort(void) {
  asm ("bkpt #0");
}
