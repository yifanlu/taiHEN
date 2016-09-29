/**
 * @brief      Internal functions and defines
 */
#ifndef TAI_HEADER
#define TAI_HEADER

#include "taihen.h"

struct _tai_inject {

};

struct _tai_hook_head {

};

struct _tai_hook {

};

typedef struct _tai_hook_head tai_hook_head_t;

typedef struct _tai_patch tai_patch_t;

struct _tai_patch {
  union {
    tai_inject_t inject;
    tai_hook_head_t hook;
  } data;
  SceUID pid;
  uint32_t module_nid;
  uintptr_t addr;
  size_t len;
  tai_patch_t *range_next;
  tai_patch_t *proc_next;
  tai_patch_t *free_next;
};

#endif
