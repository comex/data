#include "common.h"
#include "binary.h"
#include "find.h"

int main(int argc, char **argv) {
    struct binary binary;
    b_init(&binary);
    b_load_macho(&binary, argv[1], false);
    range_t range = {&binary, parse_hex_uint32(argv[2]), 0x1000};
    uint32_t bl;
    while(bl = find_bl(&range)) {
        printf("%08x -> %08x\n", range.start, bl);
    }
    return 0;
}
