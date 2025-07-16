

struct EnumDefiningType {
    char* name;
    int val;
};

struct EnumDefiningType single_enum_def = {
    .name = "single_enum",
    .val = 5
};

struct EnumDefiningType array_enum_def[] = {
    {.name = "none", .val = 0},
    {.name = "two", .val = 2},
    {.name = "one", .val = 1},
};


struct ContainingTypeOne {
    int blah;
    struct EnumDefiningType enum_def;
};

struct ContainingTypeTwo {
    char* blah;
    struct ContainingTypeOne cont_one;
};

struct ContainingTypeTwo containing_type_inst = {
    .blah = "blah",
    .cont_one = {
        .blah = 15,
        .enum_def = {
            .name = "enum_name",
            .val = 26,
        },
    },
};

