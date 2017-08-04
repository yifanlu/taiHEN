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

int hen_add_patches(void);
int hen_remove_patches(void);

/** @} */

#endif // TAI_HEN_HEADER
