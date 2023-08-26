#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>


int unconstrained_stack_memcpy_overflow(char* srcbuf, size_t count){
    char dstbuf[32] = {};
    memcpy(dstbuf, srcbuf, count);
    return 0;
}

int incorrect_size_checked_stack_memcpy_overflow(char* srcbuf, size_t count){
    char dstbuf[32] = {};
    if (count > 48) {
        return -1;
    }
    memcpy(dstbuf, srcbuf, count);
    return 0;
}

int unconstrained_stack_read_overflow(size_t count){
    char dstbuf[32] = {};
    read(0, dstbuf, count);
    return 0;
}


