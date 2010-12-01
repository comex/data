#include "common.h"
#ifdef IMG3_SUPPORT
prange_t decrypt_and_decompress(uint32_t key_bits, prange_t key, prange_t iv, prange_t output);
prange_t parse_img3(prange_t img3, uint32_t *key_bits);
prange_t parse_img3_file(char *filename, uint32_t *key_bits);
#endif
