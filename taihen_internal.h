/**
 * @brief      Internal functions and defines
 */
#ifndef TAI_INTERNAL_HEADER
#define TAI_INTERNAL_HEADER

#include <psp2kern/types.h>
#include "taihen.h"

#define FUNC_SAVE_SIZE 16

typedef struct _tai_hook_list tai_hook_list_t;

typedef struct _tai_patch tai_patch_t;

typedef struct _tai_proc tai_proc_t;

typedef struct _tai_substitute_args tai_substitute_args_t;

typedef enum {
  HOOKS,
  INJECTION
} tai_patch_type_t;

struct _tai_hook {
  tai_hook_t *next;
  void *func;
  tai_patch_t *patch;
  int refcnt;
};

struct _tai_inject {
  void *saved;
  size_t size;
  tai_patch_t *patch;
};

struct _tai_hook_list {
  uint8_t origcode[FUNC_SAVE_SIZE];
  size_t origlen;
  tai_hook_t *head;
  tai_hook_t tail;
};

struct _tai_patch {
  union {
    tai_inject_t inject;
    tai_hook_list_t hooks;
  } data;
  tai_patch_type_t type;
  SceUID pid;
  uintptr_t addr;
  size_t size;
  tai_patch_t *next;
};

struct _tai_proc {
  SceUID pid;
  tai_patch_t *head;
  tai_proc_t *next;
};

struct _tai_substitute_args {
  SceUID pid;
};

#endif // TAI_INTERNAL_HEADER
