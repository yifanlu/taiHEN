/**
 * @brief      Config and plugin loading
 */
#ifndef TAI_PLUGIN_HEADER
#define TAI_PLUGIN_HEADER

/**
 * @defgroup   plugin Plugin Loading
 * @brief      Loads config.txt and handles plugins
 *
 * @details    Plugins are loaded from the default location and then the
 *             fallback. Locks are used to ensure config does not change during
 *             parsing.
 */
/** @{ */

/** Path to the taiHEN configuration file */
#define TAIHEN_CONFIG_FILE "ux0:tai/config.txt"

/** Fallback if the configuration file is not found. */
#define TAIHEN_RECOVERY_CONFIG_FILE "ur0:tai/config.txt"

void plugin_load(const char *module, void *param);
int plugin_load_config(void);
int plugin_free_config(void);

/** @} */

#endif // TAI_PLUGIN_HEADER
