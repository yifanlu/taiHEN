/**
 * @brief      Data structure for storing patches internally
 */
#ifndef TAI_PROC_MAP_HEADER
#define TAI_PROC_MAP_HEADER

typedef struct {
  int nbuckets;
  SceUID lock;
  tai_map_func_t *map_func;
  tai_proc_t *buckets[];
} tai_proc_map_t;

/**
 * @defgroup   proc_map Process Map Interface
 */
/** @{ */

int proc_map_init(void);
void proc_map_deinit(void);
tai_proc_map_t *proc_map_alloc(int nbuckets);
void proc_map_free(tai_map_t *map);
int proc_map_try_insert(tai_proc_map_t *map, tai_patch_t *patch, tai_patch_t **existing);
int proc_map_remove_all_pid(tai_proc_map_t *map, SceUID pid, tai_patch_t **head);
int proc_map_remove(tai_range_map_t *map, tai_patch_t *patch);

/** @} */

#endif // TAI_PROC_MAP_HEADER
