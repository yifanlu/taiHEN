/**
 * @brief      Homebrew enabler patches
 */
#ifndef TAI_HEN_HEADER
#define TAI_HEN_HEADER

/**
 * @defgroup   hen Homebrew Enabler
 * @brief      Patches kernel to enable homebrew loading
 *
 * @details    Uses the taiHEN hooks system to inject hooks on SELF decryption
 *             functions to accept unsigned/unencrypted SELFs.
 */
/** @{ */

/** Path to the taiHEN configuration file */
#define TAIHEN_CONFIG_FILE "ux0:tai/config.txt"

/** Fallback if the configuration file is not found. */
#define TAIHEN_RECOVERY_CONFIG_FILE "ur0:tai/config.txt"

/**
 * @brief      Arguments passed from taiHEN to config parser back to taiHEN
 */
typedef struct _tai_plugin_load {
  SceUID pid;			///< Process to load plugin to
  int flags;			///< Flags for loading
} tai_plugin_load_t;

void hen_load_plugin(const char *module, void *param);
int hen_load_config(void);
int hen_free_config(void);
int hen_add_patches(void);
int hen_remove_patches(void);

/** @} */

#endif // TAI_HEN_HEADER
