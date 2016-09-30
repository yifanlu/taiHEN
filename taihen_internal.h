/**
 * @brief      Internal functions and defines
 */
#ifndef TAI_HEADER
#define TAI_HEADER

#include "taihen.h"

#define FUNC_SAVE_SIZE 16

struct _tai_inject {

};

struct _tai_hook_list {
  SceUID lock;
  void origcode[FUNC_SAVE_SIZE];
  size_t origlen;
  tai_hook_t *head;
  tai_hook_t tail;
};

struct _tai_hook {
  tai_hook_t *next;
  void *func;
  tai_patch_t *patch;
};

typedef struct _tai_hook_list tai_hook_list_t;

typedef struct _tai_patch tai_patch_t;

struct _tai_patch {
  union {
    tai_inject_t inject;
    tai_hook_list_t hooks;
  } data;
  SceUID pid;
  uintptr_t addr;
  size_t size;
  tai_patch_t *next;
};

typedef struct _tai_proc tai_proc_t;

struct _tai_proc {
  SceUID pid;
  tai_patch_t *head;
};

#endif
