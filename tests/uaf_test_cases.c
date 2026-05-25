/*
 * Test cases for use_after_free_finder.py
 *
 * Functions prefixed with test_uaf_ SHOULD trigger UAF findings.
 * Functions prefixed with test_no_uaf_ should NOT trigger findings.
 *
 * Compile: gcc -O0 -g -fno-builtin -o uaf_test_binary uaf_test_cases.c
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Volatile sink prevents the compiler from optimizing away
   loads/stores that we need present in the binary. */
volatile int sink;
volatile char csink;

/* ================================================================
 * POSITIVE TEST CASES - these SHOULD be detected as UAF
 * ================================================================ */

/* Basic read after free */
void test_uaf_simple_read(void) {
    char *p = (char *)malloc(32);
    p[0] = 'A';
    free(p);
    csink = p[0];
}

/* Basic write after free */
void test_uaf_simple_write(void) {
    char *p = (char *)malloc(32);
    free(p);
    p[0] = 'B';
}

/* Use through a pointer alias (q = p; free(p); use q) */
void test_uaf_alias(void) {
    char *p = (char *)malloc(32);
    char *q = p;
    free(p);
    csink = q[0];
}

/* Double free */
void test_uaf_double_free(void) {
    char *p = (char *)malloc(32);
    free(p);
    free(p);
}

/* Free in one branch, use unconditionally after merge */
void test_uaf_conditional(void) {
    char *p = (char *)malloc(32);
    if (sink) {
        free(p);
    }
    csink = p[0];
}

/* Pass freed pointer to another function */
void test_uaf_pass_to_func(void) {
    char *p = (char *)malloc(32);
    free(p);
    memset(p, 0, 32);
}

/* Struct field access after free */
struct node {
    int value;
    struct node *next;
};

void test_uaf_struct_field(void) {
    struct node *n = (struct node *)malloc(sizeof(struct node));
    n->value = 42;
    free(n);
    sink = n->value;
}

/* ================================================================
 * NEGATIVE TEST CASES - these should NOT be detected as UAF
 * ================================================================ */

/* Normal: use then free, no use after */
void test_no_uaf_normal(void) {
    char *p = (char *)malloc(32);
    p[0] = 'A';
    csink = p[0];
    free(p);
}

/* Pointer is reassigned after free via new malloc */
void test_no_uaf_reassign(void) {
    char *p = (char *)malloc(32);
    free(p);
    p = (char *)malloc(64);
    p[0] = 'C';
    csink = p[0];
    free(p);
}

/* Free path returns before the use */
void test_no_uaf_conditional_return(void) {
    char *p = (char *)malloc(32);
    if (sink) {
        free(p);
        return;
    }
    p[0] = 'D';
    csink = p[0];
    free(p);
}

int main(void) {
    test_uaf_simple_read();
    test_uaf_simple_write();
    test_uaf_alias();
    test_uaf_double_free();
    test_uaf_conditional();
    test_uaf_pass_to_func();
    test_uaf_struct_field();
    test_no_uaf_normal();
    test_no_uaf_reassign();
    test_no_uaf_conditional_return();
    return 0;
}
