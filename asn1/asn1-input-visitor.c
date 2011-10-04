/*
 * ASN.1 Input Visitor
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *  Stefan Berger     <stefanb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

/*
 * TODO:
 * - read type tag via function
 * - reading of constructed IA5Strings (etc) that need to be reassembled
 */

#include "asn1-input-visitor.h"
#include "qemu-queue.h"
#include "qemu-common.h"
#include "hw/hw.h"
#include "asn1.h"
#include "qerror.h"

#define AIV_STACK_SIZE 1024

typedef struct StackEntry
{
    uint32_t cur_pos;
} StackEntry;

struct Asn1InputVisitor
{
    Visitor visitor;
    QEMUFile *qfile;
    uint32_t cur_pos;
    StackEntry stack[AIV_STACK_SIZE];
    int nb_stack;
};

static Asn1InputVisitor *to_aiv(Visitor *v)
{
    return container_of(v, Asn1InputVisitor, visitor);
}

static void asn1_input_push(Asn1InputVisitor *aiv,
                            uint32_t cur_pos, Error **errp)
{
    aiv->stack[aiv->nb_stack].cur_pos = cur_pos;
    aiv->nb_stack++;

    if (aiv->nb_stack >= AIV_STACK_SIZE) {
        error_set(errp, QERR_BUFFER_OVERRUN);
        return;
    }
}

static uint32_t asn1_input_pop(Asn1InputVisitor *aiv, Error **errp)
{
    aiv->nb_stack--;

    if (aiv->nb_stack < 0) {
        error_set(errp, QERR_BUFFER_OVERRUN);
        return 0;
    }

    return aiv->stack[aiv->nb_stack].cur_pos;
}

static uint64_t asn1_read_length(QEMUFile *qfile, uint32_t *bytes_read,
                                 Error **errp)
{
    uint8_t byte, c, int_len;
    uint64_t len = 0;

    *bytes_read = 1;

    byte = qemu_get_byte(qfile);
    if (byte == ASN1_LENGTH_INDEFINITE) {
        return byte;
    }

    if (0 == (byte & BER_LENGTH_LONG)) {
        len = byte;
    } else {
        int_len = byte & BER_LENGTH_MASK;
        if (int_len > 8) {
            error_set(errp, QERR_INVALID_PARAMETER,
                      "ASN.1 integer length field > 8");
            return 0;
        }
        for (c = 0; c < int_len; c++) {
            len <<= 8;
            len = qemu_get_byte(qfile);
        }
        *bytes_read += int_len;
    }

    return len;
}

static void asn1_skip_bytes(Asn1InputVisitor *aiv, uint64_t to_skip,
                            Error **errp)
{
    uint8_t buf[1024];
    uint32_t skip;
    aiv->cur_pos += to_skip;

    /* skip length bytes */
    while (to_skip > 0) {
        skip = (to_skip > sizeof(buf)) ? sizeof(buf) : to_skip;
        if (qemu_get_buffer(aiv->qfile, buf, skip) != skip) {
            // FIXME: Set error code
            //error_set(errp, "Stream ended early.\n");
            return;
        }
        to_skip -= skip;
    }
}

static void asn1_skip_until_eoc(Asn1InputVisitor *aiv, unsigned nesting,
                                Error **errp)
{
    uint8_t id;
    uint64_t length;
    uint32_t bytes_read;

    while ((*errp) == NULL) {
        id = qemu_get_byte(aiv->qfile);
        aiv->cur_pos ++;
        length = asn1_read_length(aiv->qfile, &bytes_read, errp);
        if (*errp) {
            return;
        }
        aiv->cur_pos += bytes_read;
        fprintf(stderr,"%s: found id: 0x%02x, len = %lu\n",
                __func__, id, length);
        if (id == ASN1_TYPE_EOC) {
            if (length == 0) {
                fprintf(stderr, "found end! %u\n", aiv->cur_pos);
                return;
            }
            error_set(errp, QERR_INVALID_PARAMETER,
                      "ASN.1 EOC length field is invalid");
            return;
        }
        if ((id & BER_TYPE_P_C_MASK)) {
            /* constructed */
            if (length == ASN1_LENGTH_INDEFINITE) {
                asn1_skip_until_eoc(aiv, nesting+1, errp);
            } else {
                asn1_skip_bytes(aiv, length, errp);
            }
        } else {
            /* primitive */
            fprintf(stderr, "skipping an ia5string/int/bool of length "
                    "%lu.\n", length);
            asn1_skip_bytes(aiv, length, errp);
        }
    }
}

static void asn1_input_start_constructed(Visitor *v, uint8_t asn1_type,
                                   void **obj,
                                   const char *kind, const char *name,
                                   size_t size, Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    int byte;
    int64_t len;
    uint32_t bytes_for_len;

    byte = qemu_get_byte(aiv->qfile);
    if (byte != asn1_type) {
        // FIXME
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "a",
                  "b");
        return;
    }
    len = asn1_read_length(aiv->qfile, &bytes_for_len, errp);
    if (*errp) {
        return;
    }

    if (len != ASN1_LENGTH_INDEFINITE) {
        fprintf(stderr, "structure/set len: %li\n", len);
        asn1_input_push(aiv, aiv->cur_pos + 1 + bytes_for_len + len, errp);
    } else {
        fprintf(stderr, "indefinite length encoding!\n");
        asn1_input_push(aiv, 0, errp);
    }

    if (*errp) {
        return;
    }

    /* only allocating buffer once at the very beginning; assuming
       embedded structures/sets otherwise */
    if (aiv->cur_pos == 0) {
        *obj = g_malloc0(size);
        if (*obj == NULL) {
            // FIXME: Set error code
            return;
        }
    }

    aiv->cur_pos += 1 + bytes_for_len;
}

static void asn1_input_end_constructed(Visitor *v, Error **errp)
{
    uint32_t new_pos;
    Asn1InputVisitor *aiv = to_aiv(v);

    new_pos = asn1_input_pop(aiv, errp);

    if (new_pos != 0) {
        fprintf(stderr, "new_pos = %d\n", new_pos);
        aiv->cur_pos = new_pos;
    } else {
        fprintf(stderr, "searching for end...\n");
        fprintf(stderr, "cur_pos = %u\n", aiv->cur_pos);
        asn1_skip_until_eoc(aiv, 0, errp);
    }
}

static void asn1_input_start_struct(Visitor *v, void **obj, const char *kind,
                                   const char *name, size_t size, Error **errp)
{
    asn1_input_start_constructed(v, ASN1_TYPE_SEQUENCE, obj, kind, name,
                                 size, errp);
}

static void asn1_input_end_struct(Visitor *v, Error **errp)
{
    asn1_input_end_constructed(v, errp);
}

static void asn1_input_start_array(Visitor *v, void **obj,
                                   const char *name, size_t elem_count,
                                   size_t elem_size, Error **errp)
{
    asn1_input_start_constructed(v, ASN1_TYPE_SET, obj, NULL, name,
                                 elem_count * elem_size, errp);
}

static void asn1_input_next_array(Visitor *v, Error **errp)
{
    /* nothing to do here */
}

static void asn1_input_end_array(Visitor *v, Error **errp)
{
    asn1_input_end_constructed(v, errp);
}

static void asn1_input_type_int(Visitor *v, int64_t *obj, const char *name,
                                Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint8_t asn1_type;
    uint32_t bytes_for_len;
    uint64_t len;
    int c;

    asn1_type = qemu_get_byte(aiv->qfile);

    fprintf(stderr,"%s: got type: 0x%02x, expected 0x%02x\n",
            __func__, asn1_type, ASN1_TYPE_INTEGER);

    if (asn1_type != ASN1_TYPE_INTEGER) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "a",
                  "b");
        return;
    }
    len = asn1_read_length(aiv->qfile, &bytes_for_len, errp);
    fprintf(stderr, "pos: %d int len: %li, bytes_for_len=%u\n",
            aiv->cur_pos, len, bytes_for_len);

    *obj = 0;
    for (c = 0; c < len ; c++) {
        *obj <<= 8;
        *obj |= qemu_get_byte(aiv->qfile);
    }
    aiv->cur_pos += 1 + bytes_for_len + len;
    fprintf(stderr, "pos: %d int: %li\n", aiv->cur_pos, *obj);
}

static void asn1_input_type_bool(Visitor *v, bool *obj, const char *name,
                                 Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint8_t asn1_type;
    uint32_t bytes_for_len;
    uint64_t len;

    asn1_type = qemu_get_byte(aiv->qfile);
    if (asn1_type != ASN1_TYPE_BOOLEAN) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "?",
                  "bool");
        return;
    }
    len = asn1_read_length(aiv->qfile, &bytes_for_len, errp);
    fprintf(stderr, "pos: %d bool len: %li, bytes_for_len=%u\n",
            aiv->cur_pos, len, bytes_for_len);

    if (len != 1) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE,
                  "ASN.1 bool length indicator",
                  "1");
        return;
    }
    *obj = qemu_get_byte(aiv->qfile);
    aiv->cur_pos += 1 + bytes_for_len + len;
    fprintf(stderr, "pos: %d bool: %d\n", aiv->cur_pos, *obj);
}

static void asn1_input_type_str(Visitor *v, char **obj, const char *name,
                                Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint8_t asn1_type;
    uint32_t bytes_for_len;
    uint64_t len;

    // FIXME: call function to read fragmented parts

    asn1_type = qemu_get_byte(aiv->qfile);
    if ((asn1_type & 0x1f) != ASN1_TYPE_IA5STRING) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "?",
                  "string");
        return;
    }
    len = asn1_read_length(aiv->qfile, &bytes_for_len, errp);
    fprintf(stderr, "pos: %d string len: %li, bytes_for_len=%u\n",
            aiv->cur_pos, len, bytes_for_len);

    *obj = g_malloc(len+1);
    if (*obj == NULL) {
        error_set(errp, "Out of memory.\n");
        return;
    }
    if (qemu_get_buffer(aiv->qfile, (uint8_t *)*obj, len) != len) {
        //error_set(errp, "Stream ended early.\n");
        return;
    }
    (*obj)[len] = 0;

    aiv->cur_pos += 1 + bytes_for_len + len;
    fprintf(stderr, "pos: %d string: %s\n", aiv->cur_pos, *obj);
}

Visitor *asn1_input_get_visitor(Asn1InputVisitor *v)
{
    return &v->visitor;
}

void asn1_input_visitor_cleanup(Asn1InputVisitor *v)
{
    g_free(v);
}

Asn1InputVisitor *asn1_input_visitor_new(QEMUFile *qfile)
{
    Asn1InputVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.start_struct = asn1_input_start_struct;
    v->visitor.end_struct = asn1_input_end_struct;
    v->visitor.start_array = asn1_input_start_array;
    v->visitor.next_array = asn1_input_next_array;
    v->visitor.end_array = asn1_input_end_array;
    v->visitor.type_int = asn1_input_type_int;
    v->visitor.type_bool = asn1_input_type_bool;
    v->visitor.type_str = asn1_input_type_str;

    v->qfile = qfile;
    v->cur_pos = 0;

    return v;
}
