#include <glib.h>
#include "ber/ber-output-visitor.h"
#include "ber/ber-input-visitor.h"
#include "hw/hw.h"

typedef struct TestArray
{
    int64_t a;
    bool    b;
} TestArray;

#define TEST_ARRAY_SIZE 2

#define VALUE_X  0xFFFF800000000000ULL
#define VALUE_Y  (int32_t)0xFFFF8000
#define VALUE_Z  (int16_t)0xFF80
#define VALUE_ZZ -128

#define ENCODING_TYPE BER_MODE_CER

typedef struct TestStruct
{
    int64_t x;
    int32_t y;
    int16_t z;
    int8_t zz;
    bool    b;
    char   *string;
    TestArray *array;
} TestStruct;

static void visit_type_TestStruct(Visitor *v, TestStruct **obj, const char *name, Error **errp)
{
    int i;
    visit_start_struct(v, (void **)obj, "TestStruct", name, sizeof(TestStruct), errp);
    visit_type_int(v, &(*obj)->x, "x", errp);
    visit_type_int32_t(v, &(*obj)->y, "y", errp);
    visit_type_int16_t(v, &(*obj)->z, "z", errp);
    visit_type_int8_t(v, &(*obj)->zz, "zz", errp);
    visit_type_bool(v, &(*obj)->b, "b", errp);
    visit_type_str(v, &(*obj)->string, "string", errp);

    visit_start_array(v, (void **)&(*obj)->array, "TestArray", TEST_ARRAY_SIZE,
                      sizeof(TestArray), errp);
    for (i = 0; i < TEST_ARRAY_SIZE; i++) {
        visit_start_struct(v, (void **)&(*obj)->array, "array", name,
                           sizeof(TestArray), errp);
        if (i > 0) {
            visit_next_array(v, errp);
        }
        visit_type_int(v, &(*obj)->array[i].a, "array.a", errp);
        visit_type_bool(v, &(*obj)->array[i].b, "array.b", errp);
        visit_end_struct(v, errp);
    }
    visit_end_array(v, errp);

    visit_end_struct(v, errp);
}

static void visit_type_TestStruct_Skip(Visitor *v, TestStruct **obj,
                                       const char *name, Error **errp)
{
    visit_start_struct(v, (void **)obj, "TestStruct", name, sizeof(TestStruct), errp);
    visit_type_int(v, &(*obj)->x, "x", errp);
    visit_end_struct(v, errp);
}

/* test core visitor methods */
static void test_visitor_core(void)
{
    BEROutputVisitor *mo;
    BERInputVisitor *mi;
    Visitor *v;
    TestArray array[2] = {
        [0] =  {
            .a = 1234,
            .b = 1,
        },
        [1] = {
            .a = 5678,
            .b = 1,
        },
    };
    TestStruct ts = {
        .x = VALUE_X,
        .y = VALUE_Y,
        .z = VALUE_Z,
        .zz = VALUE_ZZ,
        .b = 1,
        .string = NULL,
        .array = array,
    };
    TestStruct *pts = &ts;
    Error *err = NULL;
    QEMUFile *qoutfile = qemu_bufopen("w", NULL);
    QEMUFile *qinfile;
    uint64_t len, i;
    const QEMUSizedBuffer *qsb;
    const char *hw = "Hello World.";

    ts.string = g_strdup(hw);

    mo = ber_output_visitor_new(qoutfile, ENCODING_TYPE);
    v = ber_output_get_visitor(mo);

    visit_type_TestStruct(v, &pts, NULL, &err);

    qsb = qemu_buf_get(qoutfile);
    len = qsb_get_length(qsb);

    printf("\nLength of encoded ASN.1 stream: %" PRIx64 "\n", len);
    for (i = 0; i < len ; i++) {
        printf("%02x ", qsb_get_buffer(qsb, 0)[i]);
        if ((i & 0xf) == 0xf) {
            printf("\n");
        }
    }
    printf("\n");

    qinfile = qemu_bufopen("r", qsb_clone(qsb));
    mi = ber_input_visitor_new(qinfile);
    v = ber_input_get_visitor(mi);

    pts = NULL;

    visit_type_TestStruct(v, &pts, NULL, &err);
    if (err) {
        g_error("%s", error_get_pretty(err));
    }

    g_assert(len == ber_input_get_parser_position(mi));

    g_assert(pts != NULL);
    g_assert(pts->x == VALUE_X);
    g_assert(pts->y == VALUE_Y);
    g_assert(pts->z == VALUE_Z);
    g_assert(pts->zz ==VALUE_ZZ);
    g_assert(pts->b == 1);
    g_assert(g_strcmp0(hw, pts->string) == 0);
    g_assert(pts->array[0].a == 1234);
    g_assert(pts->array[1].a == 5678);

    g_free(pts->string);
    g_free(pts->array);
    g_free(pts);

    qemu_fclose(qinfile);
    ber_input_visitor_cleanup(mi);

    qinfile = qemu_bufopen("r", qsb_clone(qsb));
    mi = ber_input_visitor_new(qinfile);
    v = ber_input_get_visitor(mi);

    pts = NULL;

    visit_type_TestStruct_Skip(v, &pts, NULL, &err);
    if (err) {
        g_error("%s", error_get_pretty(err));
    }

    g_assert(len == ber_input_get_parser_position(mi));

    qemu_fclose(qinfile);
    qemu_fclose(qoutfile);

    g_assert(pts != NULL);
    g_assert(pts->x == VALUE_X);
    g_assert(pts->y == 0); // was not parsed
    g_assert(pts->b == 0); // was not parsed
    g_assert(pts->string == NULL); // was not parsed
    g_assert(pts->array == NULL); // was not parsed

    g_free(pts->array);
    g_free(pts);

    ber_input_visitor_cleanup(mi);
    ber_output_visitor_cleanup(mo);

    g_free(ts.string);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/0.15/ber_visitor_core", test_visitor_core);

    g_test_run();

    return 0;
}
