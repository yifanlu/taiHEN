/**
 * @brief      Data structure for storing patches internally
 */
#ifndef TAI_PROC_MAP_HEADER
#define TAI_PROC_MAP_HEADER

#include <psp2kern/types.h>
#include "taihen_internal.h"

/**
 * @defgroup   proc_map Process Map Interface
 * @brief      Internal map structure
 *
 * @details    This is a thread-safe map data structure for keeping track of
 *             mappings from PID to a linked-list of patches (stored in
 *             `tai_proc_t`).
 */
/** @{ */

/**
 * @brief      The actual map in memory.
 */
typedef struct _tai_proc_map {
  int nbuckets;				///< Number of buckets set by `proc_map_alloc`
  SceUID lock;				///< Mutex for accessing buckets
  tai_proc_t *buckets[];	///< Buckets
} tai_proc_map_t;

int proc_map_init(void);
void proc_map_deinit(void);
tai_proc_map_t *proc_map_alloc(int nbuckets);
void proc_map_free(tai_proc_map_t *map);
int proc_map_try_insert(tai_proc_map_t *map, tai_patch_t *patch, tai_patch_t **existing);
int proc_map_remove_all_pid(tai_proc_map_t *map, SceUID pid, tai_patch_t **head);
int proc_map_remove(tai_proc_map_t *map, tai_patch_t *patch);

/** @} */

#endif // TAI_PROC_MAP_HEADER
