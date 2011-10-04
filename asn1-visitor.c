#include <glib.h>
#include "asn1/asn1-output-visitor.h"
#include "asn1/asn1-input-visitor.h"
#include "hw/hw.h"

typedef struct TestArray
{
    int64_t a;
    bool    b;
} TestArray;

#define TEST_ARRAY_SIZE 2

typedef struct TestStruct
{
    int64_t x;
    int64_t y;
    bool    b;
    char   *string;
    TestArray array[TEST_ARRAY_SIZE];
} TestStruct;

typedef struct TestStructList
{
    TestStruct *value;
    struct TestStructList *next;
} TestStructList;

static void visit_type_TestStruct(Visitor *v, TestStruct **obj, const char *name, Error **errp)
{
    visit_start_struct(v, (void **)obj, "TestStruct", name, sizeof(TestStruct), errp);
    visit_type_int(v, &(*obj)->x, "x", errp);
    visit_type_int(v, &(*obj)->y, "y", errp);
    visit_type_bool(v, &(*obj)->b, "b", errp);
    visit_type_str(v, &(*obj)->string, "string", errp);

    visit_start_array(v, (void **)obj, "TestArray", TEST_ARRAY_SIZE,
                      sizeof(TestArray), errp);
    int i;
    for (i = 0; i < TEST_ARRAY_SIZE; i++) {
        if (i > 0) {
            visit_next_array(v, errp);
        }
        visit_type_int(v, &(*obj)->array[i].a, "array.a", errp);
        visit_type_bool(v, &(*obj)->array[i].b, "array.b", errp);
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
    Asn1OutputVisitor *mo;
    Asn1InputVisitor *mi;
    Visitor *v;
    TestStruct ts = {
        .x = 42,
        .y = 82,
        .b = 1,
        .string = NULL,
        .array = {
            [0] =  {
                .a = 1234,
                .b = 1,
            },
            [1] = {
                .a = 5678,
                .b = 1,
            },
        },
    };
    TestStruct *pts = &ts;
    Error *err = NULL;
    QEMUFile *qoutfile = qemu_bufopen("w", NULL);
    QEMUFile *qinfile;
    uint64_t len, i;
    const QEMUSizedBuffer *qsb;
    const char *hw = "Hello World.";

    ts.string = g_strdup(hw);

    mo = asn1_output_visitor_new(qoutfile, ASN1_MODE_BER);
    v = asn1_output_get_visitor(mo);

    visit_type_TestStruct(v, &pts, NULL, &err);

    qsb = qemu_buf_get(qoutfile);
    len = qsb_get_length(qsb);
    for (i = 0; i < len ; i++) {
        printf("%02x ", qsb_get_buffer(qsb, 0)[i]);
    }
    printf("\n");

    qinfile = qemu_bufopen("r", qsb_clone(qsb));
    mi = asn1_input_visitor_new(qinfile);
    v = asn1_input_get_visitor(mi);

    pts = NULL;

    visit_type_TestStruct(v, &pts, NULL, &err);
    if (err) {
        g_error("%s", error_get_pretty(err));
    }

    g_assert(pts != NULL);
    g_assert(pts->x == 42);
    g_assert(pts->y == 82);
    g_assert(pts->b == 1);
    g_assert(g_strcmp0(hw, pts->string) == 0);
    g_assert(pts->array[0].a == 1234);
    g_assert(pts->array[1].a == 5678);

    g_free(pts->string);
    g_free(pts);

    qemu_fclose(qinfile);
    asn1_input_visitor_cleanup(mi);

    qinfile = qemu_bufopen("r", qsb_clone(qsb));
    mi = asn1_input_visitor_new(qinfile);
    v = asn1_input_get_visitor(mi);

    pts = NULL;

    visit_type_TestStruct_Skip(v, &pts, NULL, &err);
    if (err) {
        g_error("%s", error_get_pretty(err));
    }

    qemu_fclose(qinfile);
    qemu_fclose(qoutfile);

    g_assert(pts != NULL);
    g_assert(pts->x == 42);
    g_assert(pts->y == 0); // was not parsed
    g_assert(pts->b == 0); // was not parsed
    g_assert(pts->string == NULL); // was not parsed
    g_assert(pts->array[0].a == 0); // was not parsed
    g_assert(pts->array[1].a == 0); // was not parsed

    g_free(pts);

    asn1_input_visitor_cleanup(mi);
    asn1_output_visitor_cleanup(mo);

    g_free(ts.string);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/0.15/asn1_visitor_core", test_visitor_core);

    g_test_run();

    return 0;
}
