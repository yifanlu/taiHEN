/* hen.c -- kernel signature patches
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/ctrl.h>
#include <psp2kern/types.h>
#include <psp2kern/kernel/sysmem.h>
#include <string.h>
#include "error.h"
#include "hen.h"
#include "module.h"
#include "patches.h"
#include "taihen_internal.h"

/** The Vita supports a max of 8 segments for ET_SCE_RELEXEC type */
#define MAX_SEGMENTS 8

/** Should be same on all current firmware, but this may change. */
#define OFFSET_PATCH_ARG 168

/*
 *  S/ELF header
 */
/** @{ */
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef int32_t Elf32_Sword;
typedef void * Elf32_Addr;
typedef size_t Elf32_Off;

#define EI_NIDENT 16

typedef struct {
  unsigned char e_ident[EI_NIDENT]; /* ident bytes */
  Elf32_Half  e_type;     /* file type */
  Elf32_Half  e_machine;    /* target machine */
  Elf32_Word  e_version;    /* file version */
  Elf32_Addr  e_entry;    /* start address */
  Elf32_Off e_phoff;    /* phdr file offset */
  Elf32_Off e_shoff;    /* shdr file offset */
  Elf32_Word  e_flags;    /* file flags */
  Elf32_Half  e_ehsize;   /* sizeof ehdr */
  Elf32_Half  e_phentsize;    /* sizeof phdr */
  Elf32_Half  e_phnum;    /* number phdrs */
  Elf32_Half  e_shentsize;    /* sizeof shdr */
  Elf32_Half  e_shnum;    /* number shdrs */
  Elf32_Half  e_shstrndx;   /* shdr string index */
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
  uint32_t magic;                 /* 53434500 = SCE\0 */
  uint32_t version;               /* header version 3*/
  uint16_t sdk_type;              /* */
  uint16_t header_type;           /* 1 self, 2 unknown, 3 pkg */
  uint32_t metadata_offset;       /* metadata offset */
  uint64_t header_len;            /* self header length */
  uint64_t elf_filesize;          /* ELF file length */
  uint64_t self_filesize;         /* SELF file length */
  uint64_t unknown;               /* UNKNOWN */
  uint64_t self_offset;           /* SELF offset */
  uint64_t appinfo_offset;        /* app info offset */
  uint64_t elf_offset;            /* ELF #1 offset */
  uint64_t phdr_offset;           /* program header offset */
  uint64_t shdr_offset;           /* section header offset */
  uint64_t section_info_offset;   /* section info offset */
  uint64_t sceversion_offset;     /* version offset */
  uint64_t controlinfo_offset;    /* control info offset */
  uint64_t controlinfo_size;      /* control info size */
  uint64_t padding;               
} __attribute__((packed)) self_header_t;

typedef struct {
  uint64_t offset;
  uint64_t size;
  uint32_t compressed; // 2=compressed
  uint32_t unknown1;
  uint32_t encrypted; // 1=encrypted
  uint32_t unknown2;
} __attribute__((packed)) self_section_info_t;
/** @} */

/** Hook reference to `parse_headers` */
static tai_hook_ref_t g_parse_headers_hook;

/** Hook reference to `setup_buffer` */
static tai_hook_ref_t g_setup_buffer_hook;

/** Hook reference to `decrypt_buffer` */
static tai_hook_ref_t g_decrypt_buffer_hook;

/** Hook reference to `decrypt_buffer` */
static tai_hook_ref_t g_rif_check_vita_hook;

/** Hook reference to `decrypt_buffer` */
static tai_hook_ref_t g_rif_check_psp_hook;

/** Hook reference to `rif_get_info` */
static tai_hook_ref_t g_rif_get_info_hook;

/** Hook reference to check in `sceNpDrmPackageCheck` */
static tai_hook_ref_t g_package_check_hook;

/** Hook reference to check in `sceNpDrmPackageCheck` */
static tai_hook_ref_t g_package_check_2_hook;

/** Hook reference to `start_preloaded_modules */
static tai_hook_ref_t g_start_preloaded_modules_hook;

/** Hook reference to `nid_poison` */
static tai_hook_ref_t g_nid_poison_hook;

/** Hook reference to `unload_process` */
static tai_hook_ref_t g_unload_process_hook;

/** References to the hooks */
static SceUID g_hooks[11];

/** Is the current decryption a homebrew? */
static int g_is_homebrew;

/** Cache of segment info entries from SELF header */
static self_section_info_t g_seg_info[MAX_SEGMENTS];

/**
 * @brief      Patch for parsing SELF headers
 *
 * @param[in]  ctx      The decrypt context
 * @param[in]  headers  The SELF header buffer
 * @param[in]  len      The header length
 * @param      args     The arguments
 *
 * @return     Zero on success, < 0 on error
 */
static int parse_headers_patched(int ctx, const void *headers, size_t len, void *args) {
  self_header_t *self;
  Elf32_Ehdr *elf;
  int ret;
  int num_segs;

  memset(&g_seg_info, 0, sizeof(g_seg_info));
  if (len >= sizeof(self_header_t) && len >= sizeof(Elf32_Ehdr)) {
    self = (self_header_t *)headers;
    if (self->elf_offset <= len - sizeof(Elf32_Ehdr)) {
      elf = (Elf32_Ehdr *)(headers + self->elf_offset);
      num_segs = elf->e_phnum;
      if (num_segs <= MAX_SEGMENTS && 
          self->section_info_offset < self->section_info_offset + num_segs * sizeof(self_section_info_t) &&
          self->section_info_offset + num_segs * sizeof(self_section_info_t) < len
         ) {
        memcpy(&g_seg_info, headers + self->section_info_offset, num_segs * sizeof(self_section_info_t));
      }
    }
  }
  ret = TAI_CONTINUE(int, g_parse_headers_hook, ctx, headers, len, args);
  if (ctx == 1) { // as of 3.60, only one decrypt context exists
    if (ret < 0) {
      g_is_homebrew = 1;
      // we only do this patch if another hook hasn't modified it already
      if (*(uint32_t *)(args + OFFSET_PATCH_ARG) == 0) {
        *(uint32_t *)(args + OFFSET_PATCH_ARG) = 0x20;
      }
      ret = 0;
    } else {
      g_is_homebrew = 0;
    }
    LOG("parse ret %x, decrypt is homebrew? %d", ret, g_is_homebrew);
  }
  return ret;
}

/**
 * @brief      Patch for setting up decrypt buffer
 *
 * @param[in]  ctx     The decrypt context
 * @param[in]  segidx  The ELF segment index to decrypt
 *
 * @return     1 for non-compressed, 2 for compressed buffer, < 0 on error
 */
static int setup_buffer_patched(int ctx, int segidx) {
  int ret;

  ret = TAI_CONTINUE(int, g_setup_buffer_hook, ctx, segidx);
  if (ctx == 1 && g_is_homebrew && segidx < MAX_SEGMENTS) {
    ret = g_seg_info[segidx].compressed;
    LOG("segidx %d, compression type: %d", segidx, ret);
  }
  return ret;
}

/**
 * @brief        Patch for decrypting a buffer
 *
 * @param[in]    ctx     The decrypt context
 * @param[inout] buffer  The encrypted buffer to decrypt in place
 * @param[in]    len     The length of the buffer
 *
 * @return       Zero on success, < 0 on error
 */
static int decrypt_buffer_patched(int ctx, void *buffer, size_t len) {
  int ret;

  ret = TAI_CONTINUE(int, g_decrypt_buffer_hook, ctx, buffer, len);
  if (ctx == 1 && g_is_homebrew) {
    LOG("patching decrypt buffer bypass");
    ret = 0;
  }
  return ret;
}

/**
 * @brief      Patch for some rif checking
 *
 * @param[in]  a1    Unknown
 * @param[in]  a2    Unknown
 * @param[in]  a3    Unknown
 * @param[in]  a4    Unknown
 * @param[in]  a5    Unknown
 * @param[in]  a6    Unknown
 *
 * @return     Unknown
 */
static int rif_check_vita_patched(int a1, int a2, int a3, int a4, int a5, int a6) {
  int ret;
  ret = TAI_CONTINUE(int, g_rif_check_vita_hook, a1, a2, a3, a4, a5, a6);
  if (ret == 0x80870003) {
    LOG("patched rif check return: %x => 0", ret);
    ret = 0;
  }
  return ret;
}

/**
 * @brief      Patch for some rif checking used by SceCompat
 *
 * @param[in]  a1    Unknown
 * @param[in]  a2    Unknown
 * @param[in]  a3    Unknown
 * @param[in]  a4    Unknown
 * @param[in]  a5    Unknown
 *
 * @return     Unknown
 */
static int rif_check_psp_patched(int a1, int a2, int a3, int a4, int a5) {
  int ret;
  ret = TAI_CONTINUE(int, g_rif_check_psp_hook, a1, a2, a3, a4, a5);
  if (ret == 0x80870003) {
    LOG("patched rif check return: %x => 0", ret);
    ret = 0;
  }
  return ret;
}

/**
 * @brief      Patch for reading rif
 *
 * @param[in]  a1    Unknown
 * @param[in]  a2    Unknown
 * @param[in]  a3    Unknown
 * @param[in]  a4    Unknown
 * @param[in]  a5    Unknown
 * @param[in]  a6    Unknown
 * @param[in]  a7    Unknown
 * @param[in]  a8    Unknown
 * @param[in]  a9    Unknown
 * @param[in]  a10   Unknown
 * @param[in]  a11   Unknown
 * @param[in]  a12   Unknown
 *
 * @return     Unknown
 */
static int rif_get_info_patched(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12) {
  int ret;
  ret = TAI_CONTINUE(int, g_rif_get_info_hook, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
  if (ret == 0x80870003) {
    LOG("patched rif check return: %x => 0", ret);
    ret = 0;
  }
  return ret;
}

/**
 * @brief      Patch for checking if a fpkg support is enabled
 *
 * @return     Zero if valid, < 0 on error
 */
static int package_check_patched(void) {
  int ret;
  ret = TAI_CONTINUE(int, g_package_check_hook);
  LOG("patching fpkg enabled: %x => 1", ret);
  return 1;
}

/**
 * @brief      Patch for checking if a fpkg support is enabled
 *
 * @return     Zero if valid, < 0 on error
 */
static int package_check_2_patched(void) {
  int ret;
  ret = TAI_CONTINUE(int, g_package_check_2_hook);
  LOG("patching fpkg enabled: %x => 1", ret);
  return 1;
}

/**
 * @brief      Patch to disable NID poisoning
 * 
 * This function is actually a memset of 32-bit width.
 *
 * @param[in]  dst   The destination in user address space
 * @param[in]  set   What to write
 * @param[in]  len   The length
 *
 * @return     Zero
 */
static int nid_poison_patched(uintptr_t dst, int set, size_t len) {
  // we're breaking the rules here. we don't call TAI_CONTINUE
  // because we do not want the effect to take place
  //LOG("patched out nid poison request: %p, %x, len: %x", dst, set, len);
  return 0;
}

/**
 * @brief      Patch for unloading a process
 *
 * @param[in]  pid    The process being unloaded
 *
 * @return     Zero on success, < 0 on error
 */
static int unload_process_patched(SceUID pid) {
  int ret;

  LOG("unloading pid:%x", pid);
  ret = tai_try_cleanup_process(pid);
  LOG("cleanup: %x", ret);
  ret = TAI_CONTINUE(int, g_unload_process_hook, pid);
  LOG("process unloaded: %x", ret);

  return ret;
}

/**
 * @brief      Patch for loading a process
 *
 *             This event happens after the default list of modules are loaded
 *             for a process. We used to hook at that point, but because of a
 *             SCE bug, we cannot have > 15 preloaded modules. Instead now we
 *             hook at the point those preloaded modules start.
 *
 *             If the user hold the L button while the application is loading,
 *             plugins will be skipped.
 *
 * @param[in]  pid   The process being started
 *
 * @return     Zero on success, < 0 on error
 */
static int start_preloaded_modules_patched(SceUID pid) {
  SceCtrlData ctrl;
  int ret;
  char titleid[32];

  LOG("starting all default modules for %x...", pid);
  ret = TAI_CONTINUE(int, g_start_preloaded_modules_hook, pid);

  ksceCtrlPeekBufferPositive(0, &ctrl, 1);
  LOG("buttons held: 0x%08X", ctrl.buttons);
  if (ctrl.buttons & (SCE_CTRL_LTRIGGER | SCE_CTRL_L1)) {
    LOG("skipping plugin loading");
    return ret;
  }

  ksceKernelGetProcessTitleId(pid, titleid, 32);
  LOG("title started: %s, pid: %x, loading plugins...", titleid, pid);

  taiLoadPluginsForTitleForKernel(pid, titleid, 0);

  return ret;
}

/**
 * @brief      Add kernel patches to disable SELF signature checks
 *
 * @return     Zero on success, < 0 on error
 */
int hen_add_patches(void) {
  memset(g_hooks, 0, sizeof(g_hooks));
  g_hooks[0] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_parse_headers_hook, 
                                              "SceKernelModulemgr", 
                                              0x7ABF5135, // SceSblAuthMgrForKernel
                                              0xF3411881, 
                                              parse_headers_patched);
  if (g_hooks[0] < 0) goto fail;
  LOG("parse_headers_patched added");
  g_hooks[1] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_setup_buffer_hook, 
                                              "SceKernelModulemgr", 
                                              0x7ABF5135, // SceSblAuthMgrForKernel
                                              0x89CCDA2C, 
                                              setup_buffer_patched);
  if (g_hooks[1] < 0) goto fail;
  LOG("setup_buffer_patched added");
  g_hooks[2] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_decrypt_buffer_hook, 
                                              "SceKernelModulemgr", 
                                              0x7ABF5135, // SceSblAuthMgrForKernel
                                              0xBC422443, 
                                              decrypt_buffer_patched);
  if (g_hooks[2] < 0) goto fail;
  LOG("decrypt_buffer_patched added");
  g_hooks[3] = taiHookFunctionExportForKernel(KERNEL_PID, 
                                              &g_rif_check_vita_hook, 
                                              "SceNpDrm", 
                                              0xD84DC44A, // SceNpDrmForDriver
                                              0x723322B5, 
                                              rif_check_vita_patched);
  if (g_hooks[3] < 0) goto fail;
  LOG("rif_check_vita added");
  g_hooks[4] = taiHookFunctionExportForKernel(KERNEL_PID, 
                                              &g_rif_check_psp_hook, 
                                              "SceNpDrm", 
                                              0xD84DC44A, // SceNpDrmForDriver
                                              0xDACB71F4, 
                                              rif_check_psp_patched);
  if (g_hooks[4] < 0) goto fail;
  LOG("rif_check_psp added");
  g_hooks[5] = taiHookFunctionExportForKernel(KERNEL_PID, 
                                              &g_rif_get_info_hook, 
                                              "SceNpDrm", 
                                              0xD84DC44A, // SceNpDrmForDriver
                                              0xDB406EAE, 
                                              rif_get_info_patched);
  if (g_hooks[5] < 0) goto fail;
  LOG("rif_get_info added");
  g_hooks[6] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_package_check_hook, 
                                              "SceNpDrm", 
                                              0xFD00C69A, // SceSblAIMgrForDriver
                                              0xD78B04A2,
                                              package_check_patched);
  LOG("package_check added");
  if (g_hooks[6] < 0) goto fail;
  g_hooks[7] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_package_check_2_hook, 
                                              "SceNpDrm", 
                                              0xFD00C69A, // SceSblAIMgrForDriver
                                              0xF4B98F66,
                                              package_check_2_patched);
  LOG("package_check_2 added");
  if (g_hooks[7] < 0) goto fail;
  g_hooks[8] = taiHookFunctionExportForKernel(KERNEL_PID, 
                                              &g_start_preloaded_modules_hook, 
                                              "SceKernelModulemgr", 
                                              0xC445FA63, // SceModulemgrForKernel
                                              0x432DCC7A,
                                              start_preloaded_modules_patched);
  if (g_hooks[8] < 0) goto fail;
  LOG("start_preloaded_modules_patched added");
  g_hooks[9] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_nid_poison_hook, 
                                              "SceKernelModulemgr", 
                                              0x63A519E5, // SceSysmemForKernel
                                              0xECF9435A, 
                                              nid_poison_patched);
  if (g_hooks[9] < 0) goto fail;
  LOG("nid_poison_patched added");
  g_hooks[10] = taiHookFunctionImportForKernel(KERNEL_PID, 
                                              &g_unload_process_hook, 
                                              "SceProcessmgr", 
                                              0xC445FA63, // SceModulemgrForKernel
                                              0x0E33258E, 
                                              unload_process_patched);
  if (g_hooks[10] < 0) goto fail;
  LOG("unload_process_patched added");

  return TAI_SUCCESS;
fail:
  if (g_hooks[0] >= 0) {
    taiHookReleaseForKernel(g_hooks[0], g_parse_headers_hook);
  }
  if (g_hooks[1] >= 0) {
    taiHookReleaseForKernel(g_hooks[1], g_setup_buffer_hook);
  }
  if (g_hooks[2] >= 0) {
    taiHookReleaseForKernel(g_hooks[2], g_decrypt_buffer_hook);
  }
  if (g_hooks[3] >= 0) {
    taiHookReleaseForKernel(g_hooks[3], g_rif_check_vita_hook);
  }
  if (g_hooks[4] >= 0) {
    taiHookReleaseForKernel(g_hooks[4], g_rif_check_psp_hook);
  }
  if (g_hooks[5] >= 0) {
    taiHookReleaseForKernel(g_hooks[5], g_rif_get_info_hook);
  }
  if (g_hooks[6] >= 0) {
    taiHookReleaseForKernel(g_hooks[6], g_package_check_hook);
  }
  if (g_hooks[7] >= 0) {
    taiHookReleaseForKernel(g_hooks[7], g_package_check_2_hook);
  }
  if (g_hooks[8] >= 0) {
    taiHookReleaseForKernel(g_hooks[8], g_start_preloaded_modules_hook);
  }
  if (g_hooks[9] >= 0) {
    taiHookReleaseForKernel(g_hooks[9], g_nid_poison_hook);
  }
  if (g_hooks[10] >= 0) {
    taiHookReleaseForKernel(g_hooks[10], g_unload_process_hook);
  }
  return TAI_ERROR_SYSTEM;
}

/**
 * @brief      Removes the kernel patches for SELF loading
 *
 * @return     Zero on success, < 0 on error
 */
int hen_remove_patches(void) {
  int ret;

  ret = taiHookReleaseForKernel(g_hooks[0], g_parse_headers_hook);
  ret |= taiHookReleaseForKernel(g_hooks[1], g_setup_buffer_hook);
  ret |= taiHookReleaseForKernel(g_hooks[2], g_decrypt_buffer_hook);
  ret |= taiHookReleaseForKernel(g_hooks[3], g_rif_check_vita_hook);
  ret |= taiHookReleaseForKernel(g_hooks[4], g_rif_check_psp_hook);
  ret |= taiHookReleaseForKernel(g_hooks[5], g_rif_get_info_hook);
  ret |= taiHookReleaseForKernel(g_hooks[6], g_package_check_hook);
  ret |= taiHookReleaseForKernel(g_hooks[7], g_package_check_2_hook);
  ret |= taiHookReleaseForKernel(g_hooks[8], g_start_preloaded_modules_hook);
  ret |= taiHookReleaseForKernel(g_hooks[9], g_nid_poison_hook);
  ret |= taiHookReleaseForKernel(g_hooks[10], g_unload_process_hook);
  return ret;
}
