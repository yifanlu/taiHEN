/* compat.c -- Vita compatibility layer for POSIX unit tests
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define MAX_LOCKS 16

int locks_used[MAX_LOCKS] = {0};
pthread_mutex_t mutex[MAX_LOCKS];
pthread_mutex_t lock_lock = PTHREAD_MUTEX_INITIALIZER;

SceUID sceKernelMemPoolCreate(const char *name, SceSize size, void *opt) {
  return 1;
}

int sceKernelMemPoolDestroy(SceUID pool) {
  return 0;
}

void *sceKernelMemPoolAlloc(SceUID pool, SceSize size) {
  return malloc(size);
}

void sceKernelMemPoolFree(SceUID pool, void *ptr) {
  return free(ptr);
}

SceUID sceKernelCreateMutexForKernel(const char *name, SceUInt attr, int initCount, SceKernelMutexOptParam *option) {
  static pthread_mutexattr_t recattr;
  static int recattr_init = 0;
  int id;

  pthread_mutex_lock(&lock_lock);
  id = -1;
  if (!recattr_init) {
    pthread_mutexattr_init(&recattr);
    pthread_mutexattr_settype(&recattr, PTHREAD_MUTEX_RECURSIVE);
    recattr_init = 1;
  }
  for (int i = 0; i < MAX_LOCKS; i++) {
    if (!locks_used[i]) {
      locks_used[i] = 1;
      id = i;
    }
  }
  if (id >= 0) {
    pthread_mutex_init(&mutex[id], ((attr & SCE_KERNEL_MUTEX_ATTR_RECURSIVE) == SCE_KERNEL_MUTEX_ATTR_RECURSIVE) ? &recattr : NULL);
  }
  pthread_mutex_unlock(&lock_lock);
  return id;
}

int sceKernelDeleteMutexForKernel(SceUID mutexid) {
  pthread_mutex_lock(&lock_lock);
  pthread_mutex_destroy(&mutex[mutexid]);
  pthread_mutex_unlock(&lock_lock);
  return 0;
}

int sceKernelLockMutexForKernel(SceUID mutexid, int lockCount, unsigned int *timeout) {
  if (lockCount != 1) {
    fprintf(stderr, "sceKernelLockMutexForKernel not implemented for lockCount != 1\n");
    return -1;
  }
  if (timeout != NULL) {
    fprintf(stderr, "sceKernelLockMutexForKernel not implemented for timeout != NULL\n");
    return -1;
  }
  return pthread_mutex_lock(&mutex[mutexid]);
}

int sceKernelUnlockMutexForKernel(SceUID mutexid, int unlockCount) {
  if (unlockCount != 1) {
    fprintf(stderr, "sceKernelLockMutexForKernel not implemented for unlockCount != 1\n");
    return -1;
  }
  return pthread_mutex_unlock(&mutex[mutexid]);
}
