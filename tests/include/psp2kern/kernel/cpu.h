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

int sceKernelCpuSaveContext(int context[3]);
int sceKernelCpuRestoreContext(int context[3]);
int sceKernelCpuDisableInterrupts(void);
int sceKernelCpuEnableInterrupts(int flags);

#ifdef __cplusplus
}
#endif

#endif /* _PSP2_KERNEL_CPU_H_ */