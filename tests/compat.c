/* compat.c -- Vita compatibility layer for POSIX unit tests
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "../substitute/lib/substitute.h"
#include "../taihen_internal.h"

#define MAX_LOCKS 128
#define MAX_BLOCKS 128
#define MAX_TAI 128

#define MIRROR_FLAG 0x40000

int locks_used[MAX_LOCKS] = {0};
void *blocks_used[MAX_BLOCKS] = {0};
void *tai_used[MAX_TAI] = {0};
pthread_mutex_t mutex[MAX_LOCKS];
pthread_mutex_t lock_lock = PTHREAD_MUTEX_INITIALIZER;

const size_t g_exe_slab_item_size = sizeof(tai_hook_t);

SceUID ksceKernelCreateHeap(const char *name, SceSize size, SceKernelHeapCreateOpt *opt) {
  return 1;
}

int ksceKernelDeleteHeap(SceUID pool) {
  return 0;
}

void *ksceKernelAllocHeapMemory(SceUID pool, SceSize size) {
  return malloc(size);
}

void ksceKernelFreeHeapMemory(SceUID pool, void *ptr) {
  return free(ptr);
}

SceUID ksceKernelCreateMutex(const char *name, SceUInt attr, int initCount, SceKernelMutexOptParam *option) {
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
      break;
    }
  }
  if (id >= 0) {
    pthread_mutex_init(&mutex[id], ((attr & SCE_KERNEL_MUTEX_ATTR_RECURSIVE) == SCE_KERNEL_MUTEX_ATTR_RECURSIVE) ? &recattr : NULL);
  } else {
    fprintf(stderr, "ksceKernelCreateMutex: failed for %s\n", name);
    assert(0);
  }
  pthread_mutex_unlock(&lock_lock);
  return id;
}

int ksceKernelDeleteMutex(SceUID mutexid) {
  if (mutexid < 0) {
    fprintf(stderr, "ksceKernelDeleteMutex: invalid mutex\n");
    assert(0);
    return -1;
  }
  pthread_mutex_lock(&lock_lock);
  pthread_mutex_destroy(&mutex[mutexid]);
  locks_used[mutexid] = 0;
  pthread_mutex_unlock(&lock_lock);
  return 0;
}

int ksceKernelLockMutex(SceUID mutexid, int lockCount, unsigned int *timeout) {
  if (lockCount != 1) {
    fprintf(stderr, "ksceKernelLockMutex not implemented for lockCount != 1\n");
    return -1;
  }
  if (timeout != NULL) {
    fprintf(stderr, "ksceKernelLockMutex not implemented for timeout != NULL\n");
    return -1;
  }
  return pthread_mutex_lock(&mutex[mutexid]);
}

int ksceKernelUnlockMutex(SceUID mutexid, int unlockCount) {
  if (unlockCount != 1) {
    fprintf(stderr, "ksceKernelLockMutex not implemented for unlockCount != 1\n");
    return -1;
  }
  return pthread_mutex_unlock(&mutex[mutexid]);
}

SceUID ksceKernelAllocMemBlock(const char *name, SceKernelMemBlockType type, int size, SceKernelAllocMemBlockKernelOpt *optp) {
  size_t align = sizeof(void *);
  void *addr;
  int ret;
  int id;
  fprintf(stderr, "ksceKernelAllocMemBlock(%s, %x, %x, %p)\n", name, type, size, optp);
  if (optp != NULL && optp->size == sizeof(*optp)) {
    if (optp->alignment > 0) {
      align = optp->alignment;
    }
    if (optp->attr == 0x1000040) {
      fprintf(stderr, "mirroring: %x\n", optp->mirror_blkid);
      return optp->mirror_blkid | MIRROR_FLAG;
    }
  }
  ret = posix_memalign(&addr, align, size);
  fprintf(stderr, "posix_memalign(&addr, %zx, %x): %x, %p\n", align, size, ret, addr);
  if (ret < 0) {
    return ret;
  }

  pthread_mutex_lock(&lock_lock);
  id = -1;
  for (int i = 0; i < MAX_BLOCKS; i++) {
    if (blocks_used[i] == NULL) {
      blocks_used[i] = addr;
      id = i;
      break;
    }
  }
  if (id < 0) {
    fprintf(stderr, "ksceKernelAllocMemBlock: failed for %s\n", name);
    assert(0);
  }
  pthread_mutex_unlock(&lock_lock);
  return id;
}

int ksceKernelGetMemBlockBase(SceUID uid, void **ptr) {
  *ptr = blocks_used[uid & ~MIRROR_FLAG];
  fprintf(stderr, "ksceKernelGetMemBlockBase(%x): %p\n", uid, *ptr);
  return 0;
}

int ksceKernelFreeMemBlock(SceUID uid) {
  pthread_mutex_lock(&lock_lock);
  if (uid & MIRROR_FLAG) {
    fprintf(stderr, "freeing mirror mapping, ignored\n");
  } else {
    fprintf(stderr, "freeing block %d\n", uid);
    free(blocks_used[uid]);
    blocks_used[uid] = NULL;
  }
  pthread_mutex_unlock(&lock_lock);
  return 0;
}

void cache_flush(SceUID pid, uintptr_t vma, size_t len) {
  fprintf(stderr, "called flush for pid %x, vma %lx, len %zx\n", pid, vma, len);
}

int ksceKernelCpuUnrestrictedMemcpy(void *dst, const void *src, size_t len) {
  fprintf(stderr, "ksceKernelCpuUnrestrictedMemcpy(%p, %p, %zx)\n", dst, src, len);
  memcpy(dst, src, len);
  return 0;
}

typedef struct {
  const char *name;
  size_t itemsize;
  SceClassCallback create;
  SceClassCallback destroy;
} _SceClass;

int ksceKernelCreateClass(SceClass *cls, const char *name, void *uidclass, size_t itemsize, SceClassCallback create, SceClassCallback destroy) {
  _SceClass *clz = (_SceClass *)cls;

  clz->name = name;
  clz->itemsize = itemsize;
  clz->create = create;
  clz->destroy = destroy;
  fprintf(stderr, "ksceKernelCreateClass(%s)\n", name);
  return 0;
}

SceUID ksceKernelCreateUidObj(SceClass *cls, const char *name, SceCreateUidObjOpt *opt, SceObjectBase **obj) {
  _SceClass *clz = (_SceClass *)cls;
  void *ptr;
  int id;
  fprintf(stderr, "ksceKernelCreateUidObj(%s, %s)\n", clz->name, name);
  ptr = malloc(clz->itemsize);
  if (ptr == NULL) {
    fprintf(stderr, "out of memory\n");
    return -1;
  }
  *obj = (SceObjectBase *)ptr;
  pthread_mutex_lock(&lock_lock);
  id = -1;
  for (int i = 0; i < MAX_TAI; i++) {
    if (tai_used[i] == NULL) {
      tai_used[i] = ptr;
      id = i;
      break;
    }
  }
  if (id < 0) {
    fprintf(stderr, "ksceKernelCreateUidObj: failed for %s\n", name);
    assert(0);
  }
  pthread_mutex_unlock(&lock_lock);
  (*obj)->sce_reserved[0] = id;
  return id;
}
int ksceKernelGetObjForUid(SceUID uid, SceClass *cls, SceObjectBase **obj) {
  *obj = (SceObjectBase *)tai_used[uid];
  return 0;
}

SceClass *ksceKernelGetUidClass(void) {
  return NULL;
}

int ksceKernelDeleteUid(SceUID uid) {
  void *ptr;
  pthread_mutex_lock(&lock_lock);
  ptr = tai_used[uid];
  tai_used[uid] = NULL;
  pthread_mutex_unlock(&lock_lock);
  free(ptr);
  return 0;
}

int ksceKernelMemcpyUserToKernelForPid(SceUID pid, void *dst, uintptr_t src, size_t len) {
  fprintf(stderr, "stubbed out ksceKernelMemcpyUserToKernelForPid(%x, %p, %p, %zx)\n", pid, dst, (void *)src, len);
  return 0;
}

int ksceKernelRxMemcpyKernelToUserForPid(SceUID pid, uintptr_t dst, const void *src, size_t len) {
  fprintf(stderr, "stubbed out ksceKernelRxMemcpyKernelToUserForPid(%x, %p, %p, %zx)\n", pid, (void *)dst, src, len);
  return 0;
}

int substitute_hook_functions(const struct substitute_function_hook *hooks,
                              size_t nhooks,
                              struct substitute_function_hook_record **recordp,
                              int options) {
  fprintf(stderr, "stubbed out substitute_hook_functions\n");
  return 0;
}

int substitute_free_hooks(struct substitute_function_hook_record *records, 
                          size_t nhooks) {
  fprintf(stderr, "stubbed out substitute_free_hooks\n");
  return 0;
}

const char *substitute_strerror(int err) {
  static char buf[1024];
  sprintf(buf, "err: %x", err);
  return buf;
}
