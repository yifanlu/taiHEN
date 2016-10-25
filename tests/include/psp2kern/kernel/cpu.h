/**
 * \file
 * \brief Header file related to module management
 *
 * Copyright (C) 2015 PSP2SDK Project
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef _PSP2_KERNEL_CPU_H_
#define _PSP2_KERNEL_CPU_H_

#include <psp2/types.h>

#ifdef __cplusplus
extern "C" {
#endif



static inline void cpu_save_process_context(int context[3]) {
  asm ("mrc p15, 0, %0, c2, c0, 1" : "=r" (context[0]));
  asm ("mrc p15, 0, %0, c3, c0, 0" : "=r" (context[1]));
  asm ("mrc p15, 0, %0, c13, c0, 1" : "=r" (context[2]));
}

static inline void cpu_restore_process_context(int context[3]) {
  int cpsr;
  int tmp;

  asm volatile ("mrs %0, cpsr" : "=r" (cpsr));
  if (!(cpsr & 0x80)) {
    asm volatile ("cpsid i" ::: "memory");
  }
  asm volatile ("mrc p15, 0, %0, c13, c0, 1" : "=r" (tmp));
  tmp = (tmp & 0xFFFFFF00) | context[2];
  asm volatile ("mcr p15, 0, %0, c13, c0, 1" :: "r" (0));
  asm volatile ("isb" ::: "memory");
  asm volatile ("mcr p15, 0, %0, c2, c0, 1" :: "r" (context[0] | 0x4A));
  asm volatile ("isb" ::: "memory");
  asm volatile ("mcr p15, 0, %0, c13, c0, 1" :: "r" (tmp));
  asm volatile ("mcr p15, 0, %0, c3, c0, 0" :: "r" (context[1] & 0x55555555));
  if (!(cpsr & 0x80)) {
    asm volatile ("cpsie i" ::: "memory");
  }
}

int sceKernelCpuSaveContext(int context[3]);
int sceKernelCpuRestoreContext(int context[3]);
int sceKernelCpuDisableInterrupts(void);
int sceKernelCpuEnableInterrupts(int flags);

int sceKernelCpuDcacheAndL2Flush(void *ptr, size_t len);
int sceKernelCpuDcacheFlush(void *ptr, size_t len);
int sceKernelCpuIcacheAndL2Flush(void *ptr, size_t len);
int sceKernelCpuDcacheAndL2AndDMAFlush(void *ptr, size_t len);

int sceKernelCpuUnrestrictedMemcpy(void *dst, const void *src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _PSP2_KERNEL_CPU_H_ */