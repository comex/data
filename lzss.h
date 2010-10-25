#include <stdint.h>
uint32_t lzadler32(uint8_t *buf, int32_t len);
int decompress_lzss(uint8_t *dst, uint8_t *src, uint32_t srclen);
