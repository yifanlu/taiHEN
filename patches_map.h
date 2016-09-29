/**
 * @brief      Data structure for storing patches internally
 */
#ifndef TAI_PATCHES_MAP_HEADER
#define TAI_PATCHES_MAP_HEADER

typedef int (*tai_map_func_t)(uint32_t hint, uint32_t sel);

typedef struct {
  int nbuckets;
  SceUID lock;
  tai_map_func_t *map_func;
  tai_patch_t *buckets[];
} tai_map_t;

typedef tai_map_t tai_proc_map_t;
typedef tai_map_t tai_range_map_t;

#endif // TAI_PATCHES_MAP_HEADER
