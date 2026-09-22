/*
 * Fixture for the ghidra_api test suite.
 *
 * Deliberately exercises the shapes the API modules need and the UAF
 * fixture lacks: nested structs, structs referenced by value and by
 * pointer, arrays of structs, unions, enums, typedefs, globals of each,
 * varied function signatures, nested loops and an indirect call.
 *
 * Build with debug info so Ghidra's DWARF analyzer recovers the types:
 *     gcc -O0 -g -fno-builtin -o api_test_binary api_test_cases.c
 */

#include <stdio.h>
#include <string.h>

typedef struct Inner {
    int         id;
    char        tag[8];
} Inner;

typedef struct Middle {
    Inner       inner_value;    /* Inner by value  */
    Inner      *inner_pointer;  /* Inner by pointer */
    unsigned    flags;
} Middle;

typedef struct Outer {
    Middle      middle;
    Inner       inner_array[3];
    long        total;
} Outer;

typedef union Overlay {
    int         as_int;
    char        as_bytes[4];
} Overlay;

typedef enum Color {
    COLOR_RED = 0,
    COLOR_GREEN = 1,
    COLOR_BLUE = 2
} Color;

typedef int (*BinaryOp)(int, int);

/* globals: one instance of each shape, so defined Data exists in the listing */
Outer    g_outer;
Middle   g_middle;
Inner    g_inner;
Inner    g_inner_array[4];
Overlay  g_overlay;
Color    g_color;
int      g_counter;
char     g_name[16];
Inner   *g_inner_pointer;

/* statically initialised, so the pointer value is present in the image
   itself rather than only being written at runtime like g_inner_pointer */
Inner *const g_static_inner_pointer = &g_inner;

/* a global nothing else asserts on, for destructive retyping tests */
unsigned char g_scratch[32];

int add_op(int a, int b) { return a + b; }
int mul_op(int a, int b) { return a * b; }

/* varied signatures for function_signature_utils */
void            takes_nothing(void)                       { g_counter++; }
int             takes_one_int(int a)                      { return a + g_counter; }
long            takes_many(int a, char b, long c, void *d) { return a + b + c + (long)(size_t)d; }
Inner          *returns_pointer(void)                     { return &g_inner; }
Outer           returns_struct(void)                      { return g_outer; }
void            takes_struct_pointer(Outer *o)            { if (o) o->total++; }
void            takes_struct_value(Inner i)               { g_counter += i.id; }

/* uses the globals so they survive and get referenced */
void init_globals(void)
{
    memset(&g_outer, 0, sizeof(g_outer));
    g_outer.middle.inner_value.id = 1;
    strncpy(g_outer.middle.inner_value.tag, "outer", sizeof("outer"));
    g_outer.middle.inner_pointer = &g_inner;
    g_outer.total = 0;

    g_inner.id = 7;
    strncpy(g_inner.tag, "inner", sizeof("inner"));
    g_inner_pointer = &g_inner;

    g_middle.inner_value.id = 2;
    g_middle.inner_pointer = &g_inner_array[0];
    g_middle.flags = 0xF0F0;

    g_overlay.as_int = 0x41424344;
    g_color = COLOR_GREEN;
    strncpy(g_name, "fixture", sizeof("fixture"));
    memset(g_scratch, 0xAA, sizeof(g_scratch));
}

/* nested loops with a clear exit, for loopfinder / graph_utils */
long sum_inner_array(void)
{
    long total = 0;
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 8; j++) {
            if (g_inner_array[i].tag[j] == 0)
                break;
            total += g_inner_array[i].tag[j];
        }
        total += g_inner_array[i].id;
    }
    return total;
}

/* a self-recursive function */
int countdown(int n)
{
    if (n <= 0)
        return 0;
    return 1 + countdown(n - 1);
}

/* an indirect call through a function pointer */
int apply_op(BinaryOp op, int a, int b)
{
    if (!op)
        return 0;
    return op(a, b);
}

/* a call chain: caller -> middle_caller -> leaf */
int leaf(int x)          { return x * 2; }
int middle_caller(int x) { return leaf(x) + 1; }
int top_caller(int x)    { return middle_caller(x) + middle_caller(x + 1); }

/* two small "libraries" that share helpers, for component_utils:
 *
 *   alg_a_run -> alg_a_step -> shared_helper -> shared_leaf
 *                alg_a_step -> log_msg -> format_msg -> shared_leaf
 *   alg_b_run -> alg_b_step -> shared_helper, log_msg
 *   alg_b_run -> alg_b_extra
 *
 * log_msg is also called from main, so it is dominated by main alone.
 * ring_a and ring_b only call each other and nothing calls them: a cycle
 * with no way in and no way out, which a dominator algorithm has to be
 * wired to explicitly. */
int  shared_leaf(int x)   { g_counter += x; return g_counter; }
int  shared_helper(int x) { return shared_leaf(x) + 1; }
int  format_msg(int x)    { return shared_leaf(x) * 3; }
void log_msg(int x)       { g_counter = format_msg(x); }
int  alg_a_step(int x)    { log_msg(x); return shared_helper(x); }
int  alg_a_run(int x)     { return alg_a_step(x) + alg_a_step(x + 1); }
int  alg_b_extra(int x)   { return x ^ 0x5a; }
int  alg_b_step(int x)    { log_msg(x); return shared_helper(x) * 2; }
int  alg_b_run(int x)     { return alg_b_step(x) + alg_b_extra(x); }
int  ring_b(int n);

/* a dispatch table, and a struct that points at it, for table following:
 *   dispatch reads op_table directly (one hop)
 *   dispatch_via_struct reads g_ops.table, then the table (two hops) */
typedef struct OpTable { const BinaryOp *table; int count; } OpTable;
int  sub_op(int a, int b) { return a - b; }   /* only ever reached via op_table */
static const BinaryOp op_table[3] = { add_op, mul_op, sub_op };
OpTable g_ops = { op_table, 3 };
int  dispatch(int i, int a, int b)            { return op_table[i % 3](a, b); }
int  dispatch_via_struct(int i, int a, int b) { return g_ops.table[i % g_ops.count](a, b); }
int  ring_a(int n)        { return n > 0 ? ring_b(n - 1) : 0; }
int  ring_b(int n)        { return n > 0 ? ring_a(n - 1) : 1; }

int main(void)
{
    int i;
    init_globals();
    for (i = 0; i < 4; i++)
        g_inner_array[i].id = i;
    g_outer.total = sum_inner_array();
    g_counter = countdown(5);
    g_counter += apply_op(add_op, 2, 3);
    g_counter += apply_op(mul_op, 4, 5);
    g_counter += top_caller(1);
    g_counter += alg_a_run(1);
    g_counter += alg_b_run(2);
    log_msg(3);
    g_counter += dispatch(0, 1, 2) + dispatch_via_struct(1, 3, 4);
    takes_struct_pointer(&g_outer);
    takes_struct_value(g_inner);
    printf("%ld %d %d %d\n", g_outer.total, g_counter, (int)g_color,
           g_static_inner_pointer->id);
    return 0;
}
