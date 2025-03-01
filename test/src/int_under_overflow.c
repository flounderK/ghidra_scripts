
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int __attribute__((optimize(0))) simple_ucmp_with_sub(uint16_t out_buf_len, void* out_buf, void* in_buf, uint16_t padding, uint32_t ea_block_size) {
    int ret = 0;

    // bad check because of unsigned val
    if (ea_block_size <= out_buf_len - padding) {
        memcpy(out_buf, in_buf, out_buf_len - padding);
        goto exit;
    }
    ret = -1;

exit:
    return ret;
}
