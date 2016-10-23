/**
 * @brief      Internal functions and defines
 */
#ifndef TAI_INTERNAL_HEADER
#define TAI_INTERNAL_HEADER

#include <psp2kern/types.h>
#include <inttypes.h>
#include <stdio.h>
#include "taihen.h"
#include "slab.h"

#define LOG(fmt, ...) printf("[%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define FUNC_SAVE_SIZE 16

typedef struct _tai_hook_list tai_hook_list_t;

typedef struct _tai_hook tai_hook_t;

typedef struct _tai_patch tai_patch_t;

typedef struct _tai_proc tai_proc_t;

typedef struct _tai_substitute_args tai_substitute_args_t;

typedef enum {
  HOOKS,
  INJECTION
} tai_patch_type_t;

struct _tai_hook {
  // DO NOT MOVE THESE FIELDS AROUND WITHOUT CHANGING IT IN taihen.h TOO
  uintptr_t next_user;
  void *func;
  void *old;
  // END DO NOT MOVE
  int refcnt;
  tai_hook_t *next;
  tai_patch_t *patch;
};

struct _tai_inject {
  void *saved;
  size_t size;
  tai_patch_t *patch;
};

struct _tai_hook_list {
  void *func;
  void *old;
  void *saved;
  tai_hook_t *head;
};

struct _tai_patch {
  union {
    tai_inject_t inject;
    tai_hook_list_t hooks;
  } data;
  tai_patch_type_t type;
  SceUID uid;
  SceUID pid;
  uintptr_t addr;
  size_t size;
  tai_patch_t *next;
  struct slab_chain *slab;
};

struct _tai_proc {
  SceUID pid;
  tai_patch_t *head;
  tai_proc_t *next;
  struct slab_chain slab;
};

struct _tai_substitute_args {
  SceUID pid;
};

#endif // TAI_INTERNAL_HEADER
