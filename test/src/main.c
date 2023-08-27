#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


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


int variable_printf_arg_1(int choice) {
    const char* formatstring = NULL;
    switch (choice) {
        case 1: {
            formatstring = "One chosen\n";
            break;
        }
        case 2: {
            formatstring = "Two chosen\n";
            break;
        }
        case 3: {
            formatstring = "Three chosen\n";
            break;
        }
        default: {
            formatstring = "DEFAULT\n";
            break;
        }
    }

    printf(formatstring);
    return 0;
}

uint8_t g_GlobalArray[8];
uint8_t inner_global_oob_func(int ind, uint8_t val) {
    uint8_t oldval = g_GlobalArray[ind];
    g_GlobalArray[ind] = val;

    return oldval;
}

int outer_global_oob_func(void) {
    inner_global_oob_func(16, 0);

    return 0;
}

char* heap_overflow_from_strlen(char* str) {
    int length;
    char* newstr;
    if (str == NULL) {
        return NULL;
    }
    length = strlen(str);
    newstr = malloc(length);
    memset(newstr, 0, length);

    strcat(newstr, str);
    // strncat(newstr, str, length);  // also causes the issue
    return newstr;
}


int suspicious_malloc_size(void) {
    // anything that is malloc'd with a size of a single pointer or less is very suspicous,
    // as there is either enough space to store a single pointer with no additional data, or
    // enough space to store data that isn't a part of any data structure. Unless the data is for
    // an elasitcally sized value (like a char* that just happens to be very small) it could probably have
    // been a global.
    void* buf = malloc(sizeof(void*));
    return 0;
}

bool dead_store_elim(char* instr) {
    char buf[255];
    memset(buf, 0, sizeof(buf));
    bool ret = false;

    snprintf(buf, sizeof(buf), "%s", "blah");

    if (strcmp(buf, instr) == 0) {
        ret = true;
    }
    memset(buf, 0, sizeof(buf));  // gets optimized out because buf isn't used any more
    return ret;
}


