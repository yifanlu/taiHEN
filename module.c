/* module.c -- nid lookup utilities
 *
 * Copyright (C) 2016 Yifan Lu
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <psp2kern/types.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <string.h>
#include "error.h"
#include "taihen_internal.h"

struct sce_module_imports_1 {
  uint16_t size;               // size of this structure; 0x34
  uint16_t version;            //
  uint16_t flags;              //
  uint16_t num_functions;      // number of imported functions
  uint16_t num_vars;           // number of imported variables
  uint16_t num_tls_vars;       // number of imported TLS variables
  uint32_t reserved1;          // ?
  uint32_t lib_nid;            // NID of the module to link to
  char     *lib_name;          // name of module
  uint32_t reserved2;          // ?
  uint32_t *func_nid_table;    // array of function NIDs (numFuncs)
  void     **func_entry_table; // parallel array of pointers to stubs; they're patched by the loader to jump to the final code
  uint32_t *var_nid_table;     // NIDs of the imported variables (numVars)
  void     **var_entry_table;  // array of pointers to "ref tables" for each variable
  uint32_t *tls_nid_table;     // NIDs of the imported TLS variables (numTlsVars)
  void     **tls_entry_table;  // array of pointers to ???
};

struct sce_module_imports_2 {
  uint16_t size; // 0x24
  uint16_t version;
  uint16_t flags;
  uint16_t num_functions;
  uint32_t reserved1;
  uint32_t lib_nid;
  char     *lib_name;
  uint32_t *func_nid_table;
  void     **func_entry_table;
  uint32_t unk1;
  uint32_t unk2;
};

typedef union sce_module_imports {
  uint16_t size;
  struct sce_module_imports_1 type1;
  struct sce_module_imports_2 type2;
} sce_module_imports_t;

typedef struct sce_module_exports {
  uint16_t size;           // size of this structure; 0x20 for Vita 1.x
  uint8_t  lib_version[2]; //
  uint16_t attribute;      // ?
  uint16_t num_functions;  // number of exported functions
  uint16_t num_vars;       // number of exported variables
  uint16_t unk;
  uint32_t num_tls_vars;   // number of exported TLS variables?  <-- pretty sure wrong // yifanlu
  uint32_t lib_nid;        // NID of this specific export list; one PRX can export several names
  char     *lib_name;      // name of the export module
  uint32_t *nid_table;     // array of 32-bit NIDs for the exports, first functions then vars
  void     **entry_table;  // array of pointers to exported functions and then variables
} sce_module_exports_t;

typedef struct sce_module_info {
  uint16_t modattribute;  // ??
  uint16_t modversion;    // always 1,1?
  char     modname[27];   ///< Name of the module
  uint8_t  type;          // 6 = user-mode prx?
  void     *gp_value;     // always 0 on ARM
  uint32_t ent_top;       // beginning of the export list (sceModuleExports array)
  uint32_t ent_end;       // end of same
  uint32_t stub_top;      // beginning of the import list (sceModuleStubInfo array)
  uint32_t stub_end;      // end of same
  uint32_t module_nid;    // ID of the PRX? seems to be unused
  uint32_t field_38;      // unused in samples
  uint32_t field_3C;      // I suspect these may contain TLS info
  uint32_t field_40;      //
  uint32_t mod_start;     // 44 module start function; can be 0 or -1; also present in exports
  uint32_t mod_stop;      // 48 module stop function
  uint32_t exidx_start;   // 4c ARM EABI style exception tables
  uint32_t exidx_end;     // 50
  uint32_t extab_start;   // 54
  uint32_t extab_end;     // 58
} sce_module_info_t; // 5c?

#define MOD_LIST_SIZE (256)

/** The currently running FW version. */
static uint32_t fw_version = 0;

/**
 * @brief      Converts internal SCE structure to a usable form
 *
 *             This is needed since the internal SceKernelModulemgr structures
 *             change in different firmware versions.
 *
 * @param[in]  pid      The pid
 * @param[in]  sceinfo  Return from `ksceKernelGetModuleInternal`
 * @param[out] taiinfo  Output data structure
 *
 * @return     Zero on success, < 0 on error
 */
static int sce_to_tai_module_info(SceUID pid, void *sceinfo, tai_module_info_t *taiinfo) {
  SceKernelFwInfo fwinfo;
  char *info;

  if (fw_version == 0) {
    fwinfo.size = sizeof(fwinfo);
    if (ksceKernelGetSystemSwVersion(&fwinfo) < 0) {
      fw_version = DEFAULT_FW_VERSION;
    } else {
      fw_version = fwinfo.version;
    }
    LOG("ksceKernelGetSystemSwVersion: 0x%08X", fw_version);
  }

  if (taiinfo->size < sizeof(tai_module_info_t)) {
    LOG("Structure size too small: %d", taiinfo->size);
    return TAI_ERROR_SYSTEM;
  }

  info = (char *)sceinfo;
  if (fw_version >= 0x3600000) {
    if (pid == KERNEL_PID) {
      taiinfo->modid = *(SceUID *)(info + 0xC);
    } else {
      taiinfo->modid = *(SceUID *)(info + 0x10);
    }
    snprintf(taiinfo->name, 27, "%s", *(const char **)(info + 0x1C));
    taiinfo->name[26] = '\0';
    taiinfo->module_nid = *(uint32_t *)(info + 0x30);
    taiinfo->exports_start = *(uintptr_t *)(info + 0x20);
    taiinfo->exports_end = *(uintptr_t *)(info + 0x24);
    taiinfo->imports_start = *(uintptr_t *)(info + 0x28);
    taiinfo->imports_end = *(uintptr_t *)(info + 0x2C);
  } else if (fw_version >= 0x1692000) {
    if (pid == KERNEL_PID) {
      taiinfo->modid = *(SceUID *)(info + 0x0);
    } else {
      taiinfo->modid = *(SceUID *)(info + 0x4);
    }
    taiinfo->module_nid = *(uint32_t *)(info + 0x3C);
    snprintf(taiinfo->name, 27, "%s", (const char *)(info + 0xC));
    taiinfo->name[26] = '\0';
    taiinfo->exports_start = *(uintptr_t *)(info + 0x2C);
    taiinfo->exports_end = *(uintptr_t *)(info + 0x30);
    taiinfo->imports_start = *(uintptr_t *)(info + 0x34);
    taiinfo->imports_end = *(uintptr_t *)(info + 0x38);
  } else {
    LOG("Unsupported FW 0x%08X", fw_version);
    return TAI_ERROR_SYSTEM;
  }
  return TAI_SUCCESS;
}

/**
 * @brief      Finds an integer in userspace.
 * 
 * This only finds 4-byte aligned integers in the specified range!
 *
 * @param[in]  pid     The pid
 * @param[in]  src     The source
 * @param[in]  needle  The needle
 * @param[in]  size    The size
 *
 * @return     0 if not found or the offset to the needle
 */
static int find_int_for_user(SceUID pid, uintptr_t src, uint32_t needle, size_t size) {
  int my_context[3];
  int *other_context;
  int flags;
  uintptr_t end;
  uint32_t data;
  int count;
  int ret;

  count = 0;
  end = (src + size) & ~3; // align to last 4 byte boundary
  src = (src + 3) & ~3; // align to next 4 byte boundary
  if (end <= src) {
    return 0;
  }
  size = end-src;
  flags = ksceKernelCpuDisableInterrupts();
  ksceKernelCpuSaveContext(my_context);
  ret = ksceKernelGetPidContext(pid, &other_context);
  if (ret >= 0) {
    ksceKernelCpuRestoreContext(other_context);
    while (count < size) {
      asm ("ldrt %0, [%1]" : "=r" (data) : "r" (src+count));
      if (data == needle) {
        break;
      }
      count += 4;
    }
  }
  ksceKernelCpuRestoreContext(my_context);
  ksceKernelCpuEnableInterrupts(flags);
  if (ret < 0) {
    LOG("Error trying to get context for %x", pid);
    count = ret;
  }
  if (count >= size) {
    return -1;
  } else {
    return count;
  }
}

/**
 * @brief      Gets a loaded module by name or NID or both
 *
 *             If `name` is NULL, then only the NID is used to locate the loaded
 *             module. If `name` is not NULL then it will be used to lookup the
 *             loaded module. If NID is not `TAI_IGNORE_MODULE_NID`, then it
 *             will be used in the lookup too. If `name` is NULL and NID is
 *             `TAI_IGNORE_MODULE_NID` then the first module loaded for the
 *             process will be returned.
 *
 * @param[in]  pid   The pid
 * @param[in]  name  The name to lookup. Can be NULL.
 * @param[in]  nid   The nid to lookup. Can be `TAI_IGNORE_MODULE_NID`.
 * @param[out] info  The information
 *
 * @return     Zero on success, < 0 on error
 *             - TAI_ERROR_INVALID_MODULE if both `name` and NID are undefined
 *               and `pid` is KERNEL_PID.
 *             - TAI_ERROR_MODULE_OVERFLOW if there are more than
 *               `MOD_LIST_SIZE` modules loaded for the process. This is a
 *               system error and should be reported.
 */
int module_get_by_name_nid(SceUID pid, const char *name, uint32_t nid, tai_module_info_t *info) {
  SceUID modlist[MOD_LIST_SIZE];
  void *sceinfo;
  size_t count;
  int ret;
  int get_cur;

  get_cur = (name == NULL && nid == TAI_IGNORE_MODULE_NID);
  count = MOD_LIST_SIZE;
  ret = ksceKernelGetModuleList(pid, 0xff, 1, modlist, &count);
  LOG("ksceKernelGetModuleList(%x): 0x%08X, count: %d", pid, ret, count);
  if (ret < 0) {
    return ret;
  } else if (count == MOD_LIST_SIZE) {
    return TAI_ERROR_MODULE_OVERFLOW;
  }
  for (int i = (count - 1); i >= 0; i--) {
    ret = ksceKernelGetModuleInternal(modlist[i], &sceinfo);
    //LOG("ksceKernelGetModuleInternal(%x): 0x%08X", modlist[i], ret);
    if (ret < 0) {
      LOG("Error getting info for mod: %x, ret: %x", modlist[i], ret);
      return ret;
    }
    if ((ret = sce_to_tai_module_info(pid, sceinfo, info)) < 0) {
      return ret;
    }
    if (get_cur) {
      LOG("Found first module %s, NID:0x%08X", info->name, info->module_nid);
      return TAI_SUCCESS;
    } else if (name != NULL && strncmp(name, info->name, 27) == 0) {
      if (nid == TAI_IGNORE_MODULE_NID || info->module_nid == nid) {
        LOG("Found module %s, NID:0x%08X", name, info->module_nid);
        return TAI_SUCCESS;
      }
    } else if (name == NULL && info->module_nid == nid) {
      LOG("Found module %s, NID:0x%08X", info->name, info->module_nid);
      return TAI_SUCCESS;
    }
  }

  return TAI_ERROR_NOT_FOUND;
}

/**
 * @brief      Gets an offset from a segment in a module
 *
 * @param[in]  pid     The pid of caller
 * @param[in]  modid   The module to offset from
 * @param[in]  segidx  Segment in module to offset from
 * @param[in]  offset  Offset from segment
 * @param[out] addr    Output final address
 *
 * @return     Zero on success, < 0 on error
 */
int module_get_offset(SceUID pid, SceUID modid, int segidx, size_t offset, uintptr_t *addr) {
  SceKernelModuleInfo sceinfo;
  size_t count;
  int ret;

  if (segidx > 3) {
    LOG("Invalid segment index: %d", segidx);
    return TAI_ERROR_INVALID_ARGS;
  }
  LOG("Getting offset for pid:%x, modid:%x, segidx:%d, offset:%x", pid, modid, segidx, offset);
  sceinfo.size = sizeof(sceinfo);
  ret = ksceKernelGetModuleInfo(pid, modid, &sceinfo);
  LOG("ksceKernelGetModuleInfo(%x, %x): 0x%08X", pid, modid, ret);
  if (ret < 0) {
    LOG("Error getting segment info for %d", modid);
    return ret;
  }
  if (offset > sceinfo.segments[segidx].memsz) {
    LOG("Offset %x overflows segment size %x", offset, sceinfo.segments[segidx].memsz);
    return TAI_ERROR_INVALID_ARGS;
  }
  *addr = (uintptr_t)sceinfo.segments[segidx].vaddr + offset;
  LOG("found address: 0x%08X", *addr);

  return TAI_SUCCESS;
}

/**
 * @brief      Gets an exported function address
 *
 * @param[in]  pid      The pid
 * @param[in]  modname  The name of module to lookup
 * @param[in]  libnid   NID of the exporting library. Can be `TAI_ANY_LIBRARY`.
 * @param[in]  funcnid  NID of the exported function
 * @param[out] func     Output address of the function
 *
 * @return     Zero on success, < 0 on error
 */
int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func) {
  sce_module_exports_t local;
  tai_module_info_t info;
  sce_module_exports_t *export;
  uintptr_t cur;
  int found;
  int i;
  int ret;

  LOG("Getting export for pid:%x, modname:%s, libnid:%x, funcnid:%x", pid, modname, libnid, funcnid);
  info.size = sizeof(info);
  if (module_get_by_name_nid(pid, modname, TAI_IGNORE_MODULE_NID, &info) < 0) {
    LOG("Failed to find module: %s", modname);
    return TAI_ERROR_NOT_FOUND;
  }

  for (cur = info.exports_start; cur < info.exports_end; ) {
    if (pid == KERNEL_PID) {
      export = (sce_module_exports_t *)cur;
    } else {
      if ((ret = ksceKernelMemcpyUserToKernelForPid(pid, &local, cur, sizeof(local))) < 0) {
        LOG("Error trying to read address %p for %x: %x", cur, pid, ret);
        return ret;
      }
      export = &local;
    }

    if (libnid == TAI_ANY_LIBRARY || export->lib_nid == libnid) {
      if (pid == KERNEL_PID) {
        for (i = 0; i < export->num_functions; i++) {
          if (export->nid_table[i] == funcnid) {
            *func = (uintptr_t)export->entry_table[i];
            LOG("found kernel address: 0x%08X", *func);
            return TAI_SUCCESS;
          }
        }
      } else {
        found = find_int_for_user(pid, (uintptr_t)export->nid_table, funcnid, export->num_functions * 4);
        if (found >= 0) {
          if ((ret = ksceKernelMemcpyUserToKernelForPid(pid, func, (uintptr_t)export->entry_table + found, 4)) < 0) {
            LOG("Error trying to read address %p for %x: %x", (uintptr_t)export->entry_table + found, pid, ret);
            return ret;
          }
          LOG("found user address: 0x%08X", *func);
          return TAI_SUCCESS;
        }
      }
    }
    cur += export->size;
  }

  return TAI_ERROR_NOT_FOUND;
}

/**
 * @brief      Gets an imported function stub address
 *
 * @param[in]  pid            The pid
 * @param[in]  modname        The name of the module importing the function
 * @param[in]  target_libnid  The target's library NID. Can be `TAI_ANY_LIBRARY`
 * @param[in]  funcnid        The target's function NID
 * @param[out] stub           Output address to stub calling the imported
 *                            function
 *
 * @return     Zero on success, < 0 on error
 */
int module_get_import_func(SceUID pid, const char *modname, uint32_t target_libnid, uint32_t funcnid, uintptr_t *stub) {
  sce_module_imports_t local;
  tai_module_info_t info;
  sce_module_imports_t *import;
  uintptr_t cur;
  int found;
  int i;
  int ret;

  LOG("Getting import for pid:%x, modname:%s, target_libnid:%x, funcnid:%x", pid, modname, target_libnid, funcnid);
  info.size = sizeof(info);
  if (module_get_by_name_nid(pid, modname, TAI_IGNORE_MODULE_NID, &info) < 0) {
    LOG("Failed to find module: %s", modname);
    return TAI_ERROR_NOT_FOUND;
  }

  for (cur = info.imports_start; cur < info.imports_end; ) {
    if (pid == KERNEL_PID) {
      import = (sce_module_imports_t *)cur;
    } else {
      if ((ret = ksceKernelMemcpyUserToKernelForPid(pid, &local.size, cur, sizeof(local.size))) < 0) {
        LOG("Error trying to read address %p for %x: %x", cur, pid, ret);
        return ret;
      }
      if (local.size <= sizeof(local)) {
        if ((ret = ksceKernelMemcpyUserToKernelForPid(pid, &local, cur, local.size)) < 0) {
          LOG("Error trying to read address %p for %x: %x", cur, pid, ret);
          return ret;
        }
      }
      import = &local;
    }

    //LOG("import size is 0x%04X", import->size);
    if (import->size == sizeof(struct sce_module_imports_1)) {
      if (target_libnid == TAI_ANY_LIBRARY || import->type1.lib_nid == target_libnid) {
        if (pid == KERNEL_PID) {
          for (i = 0; i < import->type1.num_functions; i++) {
            if (import->type1.func_nid_table[i] == funcnid) {
              *stub = (uintptr_t)import->type1.func_entry_table[i];
              LOG("found kernel address: 0x%08X", *stub);
              return TAI_SUCCESS;
            }
          }
        } else {
          found = find_int_for_user(pid, (uintptr_t)import->type1.func_nid_table, funcnid, import->type1.num_functions * 4);
          if (found >= 0) {
            if ((ret = ksceKernelMemcpyUserToKernelForPid(pid, stub, (uintptr_t)import->type1.func_entry_table + found, 4)) < 0) {
              LOG("Error trying to read address %p for %x: %x", (uintptr_t)import->type1.func_entry_table + found, pid, ret);
              return ret;
            }
            LOG("found user address: 0x%08X", *stub);
            return TAI_SUCCESS;
          }
        }
      }
    } else if (import->size == sizeof(struct sce_module_imports_2)) {
      if (target_libnid == TAI_ANY_LIBRARY || import->type2.lib_nid == target_libnid) {
        if (pid == KERNEL_PID) {
          for (i = 0; i < import->type2.num_functions; i++) {
            if (import->type2.func_nid_table[i] == funcnid) {
              *stub = (uintptr_t)import->type2.func_entry_table[i];
              LOG("found kernel address: 0x%08X", *stub);
              return TAI_SUCCESS;
            }
          }
        } else {
          found = find_int_for_user(pid, (uintptr_t)import->type2.func_nid_table, funcnid, import->type2.num_functions * 4);
          if (found >= 0) {
            if ((ret = ksceKernelMemcpyUserToKernelForPid(pid, stub, (uintptr_t)import->type2.func_entry_table + found, 4)) < 0) {
              LOG("Error trying to read address %p for %x: %x", (uintptr_t)import->type2.func_entry_table + found, pid, ret);
              return ret;
            }
            LOG("found user address: 0x%08X", *stub);
            return TAI_SUCCESS;
          }
        }
      }
    } else {
      LOG("Invalid import size: %d", import->size);
    }
    cur += import->size;
  }

  return TAI_ERROR_NOT_FOUND;
}
