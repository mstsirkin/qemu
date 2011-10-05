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

#include "ber-input-visitor.h"
#include "qemu-queue.h"
#include "qemu-common.h"
#include "hw/hw.h"
#include "ber.h"
#include "qerror.h"

#define AIV_STACK_SIZE 1024

#define BER_DEBUG

typedef struct StackEntry
{
    uint64_t cur_pos;
} StackEntry;

struct Asn1InputVisitor
{
    Visitor visitor;
    QEMUFile *qfile;
    uint64_t cur_pos;
    StackEntry stack[AIV_STACK_SIZE];
    int nb_stack;
};

static Asn1InputVisitor *to_aiv(Visitor *v)
{
    return container_of(v, Asn1InputVisitor, visitor);
}

static void ber_input_push(Asn1InputVisitor *aiv,
                            uint64_t cur_pos, Error **errp)
{
    aiv->stack[aiv->nb_stack].cur_pos = cur_pos;
    aiv->nb_stack++;

    if (aiv->nb_stack >= AIV_STACK_SIZE) {
        error_set(errp, QERR_BUFFER_OVERRUN);
        return;
    }
}

static uint64_t ber_input_pop(Asn1InputVisitor *aiv, Error **errp)
{
    aiv->nb_stack--;

    if (aiv->nb_stack < 0) {
        error_set(errp, QERR_BUFFER_OVERRUN);
        return 0;
    }

    return aiv->stack[aiv->nb_stack].cur_pos;
}

static uint8_t ber_read_type(Asn1InputVisitor *aiv, Error **errp)
{
    uint8_t type;

    type = qemu_get_byte(aiv->qfile);
    aiv->cur_pos ++;

    return type;
}

static uint64_t ber_read_length(Asn1InputVisitor *aiv, bool *is_indefinite,
                                 Error **errp)
{
    uint8_t byte, c, int_len;
    uint64_t len = 0;
    QEMUFile *qfile = aiv->qfile;

    *is_indefinite = false;

    byte = qemu_get_byte(qfile);
    aiv->cur_pos++;

    if (byte == BER_LENGTH_INDEFINITE) {
        *is_indefinite = true;
        return 0;
    }

    if (!(byte & BER_LENGTH_LONG)) {
        len = byte;
    } else {
        int_len = byte & BER_LENGTH_MASK;
        if (int_len > 8) {
            char buf[1024];
            snprintf(buf, sizeof(buf), "ASN.1 integer length field %d > 8",
                     int_len);
            /* Length can be up to 127 byte, but it seems
             * safe to assume any input will be < 1TB in length. */
            error_set(errp, QERR_INVALID_PARAMETER, buf);
            return ~0x0ULL;
        }
        for (c = 0; c < int_len; c++) {
            len <<= 8;
            len = qemu_get_byte(qfile);
        }
        aiv->cur_pos += int_len;
    }

    return len;
}

static void ber_skip_bytes(Asn1InputVisitor *aiv, uint64_t to_skip,
                            Error **errp)
{
    uint8_t buf[1024];
    uint32_t skip;
    aiv->cur_pos += to_skip;

    /* skip length bytes */
    while (to_skip > 0) {
        skip = MIN(to_skip, sizeof(buf));
        if (qemu_get_buffer(aiv->qfile, buf, skip) != skip) {
            error_set(errp, QERR_STREAM_ENDED);
            return;
        }
        to_skip -= skip;
    }
}

static void ber_skip_until_eoc(Asn1InputVisitor *aiv, Error **errp)
{
    uint8_t ber_type;
    uint64_t length;
    bool is_indefinite;
    uint64_t indefinite_nesting = 1;

    while ((*errp) == NULL) {
        ber_type = ber_read_type(aiv, errp);
        if (*errp) {
            return;
        }

        length = ber_read_length(aiv, &is_indefinite, errp);
        if (*errp) {
            return;
        }
        if (ber_type == BER_TYPE_EOC) {
            // TODO: set errp
            if (length) {
                error_set(errp, QERR_INVALID_PARAMETER,
                          "ASN.1 EOC length field is invalid");
                return;
            }
            if (!indefinite_nesting) {
                error_set(errp, QERR_INVALID_PARAMETER,
                          "ASN.1 EOC not within an indefinite length");
                return;
            }
#ifdef BER_DEBUG
                fprintf(stderr, "found end! nesting=%" PRIdMAX ", pos=%" PRIu64 "\n",
                        indefinite_nesting, aiv->cur_pos);
#endif
            if (!--indefinite_nesting) {
                return;
            }
        }
        if (is_indefinite) {
            if ((ber_type & BER_TYPE_P_C_MASK) == BER_TYPE_PRIMITIVE) {
                error_set(errp, QERR_INVALID_PARAMETER,
                          "ASN.1 indefinite length in a primitive type.");
                return;
            }
            if (indefinite_nesting == ~0x0ULL) {
                error_set(errp, QERR_INVALID_PARAMETER,
                          "ASN.1 indefinite nesting level is too large.");
                return;
            }
            ++indefinite_nesting;
        } else {
#ifdef BER_DEBUG
            fprintf(stderr, "skipping type '%s' of length "
                    "%" PRIu64 ".\n", ber_type_to_str(ber_type), length);
#endif
            ber_skip_bytes(aiv, length, errp);
        }
    }
}

static void ber_input_start_constructed(Visitor *v, uint8_t exp_ber_type,
                                   void **obj,
                                   const char *kind, const char *name,
                                   size_t size, Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint8_t ber_type;
    int64_t len;
    bool is_indefinite;

    ber_type = ber_read_type(aiv, errp);
    if (*errp) {
        return;
    }

    if ((ber_type & 0x1f) != exp_ber_type) {
        char buf[1024];
	sprintf(buf, "%s at offset %" PRIx64 "\n",
                  ber_type_to_str(exp_ber_type), aiv->cur_pos);

        error_set(errp, QERR_INVALID_PARAMETER_TYPE,
                  ber_type_to_str(ber_type),
                  buf);
        return;
    }

    if ((ber_type & BER_TYPE_P_C_MASK) == 0) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE,
                  "primitive type",
                  "constructed type");
        return;
    }

    len = ber_read_length(aiv, &is_indefinite, errp);
    if (*errp) {
        return;
    }

    if (!is_indefinite) {
#ifdef BER_DEBUG
        fprintf(stderr, "structure/set len: %" PRIi64 "\n", len);
#endif
        ber_input_push(aiv, aiv->cur_pos + len, errp);
    } else {
#ifdef BER_DEBUG
        fprintf(stderr, "indefinite length encoding!\n");
#endif
        ber_input_push(aiv, 0, errp);
    }

    if (*errp) {
        return;
    }

    if (*obj == NULL) {
        *obj = g_malloc0(size);
#ifdef BER_DEBUG
        fprintf(stderr, "for type '%s' allocated buffer at %p, size = %zu\n",
                ber_type_to_str(ber_type), *obj, size);
#endif
        if (*obj == NULL) {
            error_set(errp, QERR_OUT_OF_MEMORY);
            return;
        }
    }
}

static void ber_input_end_constructed(Visitor *v, Error **errp)
{
    uint64_t new_pos;
    Asn1InputVisitor *aiv = to_aiv(v);

    new_pos = ber_input_pop(aiv, errp);

    if (new_pos != 0) {
#ifdef BER_DEBUG
        fprintf(stderr, "new_pos = %" PRIu64 "\n", new_pos);
#endif
        aiv->cur_pos = new_pos;
    } else {
#ifdef BER_DEBUG
        fprintf(stderr, "searching for end...\n");
        fprintf(stderr, "cur_pos = %" PRIu64 "\n", aiv->cur_pos);
#endif
        ber_skip_until_eoc(aiv, errp);
    }
}

static void ber_input_start_struct(Visitor *v, void **obj, const char *kind,
                                   const char *name, size_t size, Error **errp)
{
    ber_input_start_constructed(v, BER_TYPE_SEQUENCE, obj, kind, name,
                                 size, errp);
}

static void ber_input_end_struct(Visitor *v, Error **errp)
{
    ber_input_end_constructed(v, errp);
}

static void ber_input_start_array(Visitor *v, void **obj,
                                   const char *name, size_t elem_count,
                                   size_t elem_size, Error **errp)
{
    ber_input_start_constructed(v, BER_TYPE_SET, obj, NULL, name,
                                 elem_count * elem_size, errp);
}

static void ber_input_next_array(Visitor *v, Error **errp)
{
    /* nothing to do here */
}

static void ber_input_end_array(Visitor *v, Error **errp)
{
    ber_input_end_constructed(v, errp);
}

static void ber_input_integer(Visitor *v, uint8_t *obj, uint8_t maxbytes,
                               Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint8_t ber_type;
    bool is_indefinite;
    uint64_t len;
    uint64_t val = 0;
    int c;

#ifdef BER_DEBUG
    fprintf(stderr,"reading int to %p\n", obj);
#endif

    ber_type = ber_read_type(aiv, errp);
    if (*errp) {
        return;
    }

#ifdef BER_DEBUG
    fprintf(stderr,"%s: got type: 0x%02x, expected 0x%02x\n",
            __func__, ber_type, BER_TYPE_INTEGER);
#endif

    if (ber_type != BER_TYPE_INTEGER) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE,
                  ber_type_to_str(ber_type),
                  ber_type_to_str(BER_TYPE_INTEGER));
        return;
    }
    len = ber_read_length(aiv, &is_indefinite, errp);
#ifdef BER_DEBUG
    fprintf(stderr, "pos: %" PRIu64 " int len: %" PRIi64 "\n",
            aiv->cur_pos, len);
#endif

    if (is_indefinite || len > maxbytes) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE,
                  "ASN.1 bool int indicator is indefinite or too large",
                  "[1..8]");
        return;
    }

    for (c = 0; c < len ; c++) {
        val <<= 8;
        val |= qemu_get_byte(aiv->qfile);
        if (c == 0 && (val & 0x80) == 0x80) {
            /* sign extend */
            val |= 0xFFFFFFFFFFFFFF00ULL;
        }
    }
    aiv->cur_pos += len;
#ifdef BER_DEBUG
    fprintf(stderr, "pos: %" PRIu64 " int: %" PRIx64 "\n", aiv->cur_pos, val);
#endif

    memcpy(obj, &val, maxbytes);
}

static void ber_input_type_int(Visitor *v, int64_t *obj, const char *name,
                                Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_uint8_t(Visitor *v, uint8_t *obj,
                                    const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_uint16_t(Visitor *v, uint16_t *obj,
                                     const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_uint32_t(Visitor *v, uint32_t *obj,
                                     const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_uint64_t(Visitor *v, uint64_t *obj,
                                     const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_int8_t(Visitor *v, int8_t *obj,
                                   const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_int16_t(Visitor *v, int16_t *obj,
                                    const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_int32_t(Visitor *v, int32_t *obj,
                                    const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_int64_t(Visitor *v, int64_t *obj,
                                    const char *name, Error **errp)
{
    ber_input_integer(v, (uint8_t *)obj, sizeof(*obj), errp);
}

static void ber_input_type_bool(Visitor *v, bool *obj, const char *name,
                                 Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint8_t ber_type;
    bool is_indefinite;
    uint64_t len;

    ber_type = ber_read_type(aiv, errp);
    if (*errp) {
        return;
    }

    if (ber_type != BER_TYPE_BOOLEAN) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE,
                  ber_type_to_str(ber_type),
                  ber_type_to_str(BER_TYPE_BOOLEAN));
        return;
    }
    len = ber_read_length(aiv, &is_indefinite, errp);
#ifdef BER_DEBUG
    fprintf(stderr, "pos: %" PRIu64 " bool len: %" PRIi64 "\n",
            aiv->cur_pos, len);
#endif

    if (is_indefinite || len != 1) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE,
                  "ASN.1 bool length indicator is indefinite or != 1",
                  "1");
        return;
    }
    *obj = qemu_get_byte(aiv->qfile);
    aiv->cur_pos += len;

#ifdef BER_DEBUG
    fprintf(stderr, "pos: %" PRIu64 " bool: %d\n", aiv->cur_pos, *obj);
#endif
}

/* Function for recursive reading of fragmented primitives */
static uint32_t ber_input_fragment(Asn1InputVisitor *aiv,
                                    uint8_t exp_ber_type,
                                    uint8_t **buffer, uint32_t *buffer_len,
                                    uint32_t offset, uint32_t nesting,
                                    bool indefinite, uint64_t max_pos,
                                    const char *name, Error **errp)
{
    uint8_t ber_type;
    uint32_t bytes_read = 0;
    bool is_indefinite;
    uint64_t len;

    assert((exp_ber_type & BER_TYPE_CONSTRUCTED) == 0);

    ber_type = ber_read_type(aiv, errp);
    if (*errp) {
        return 0;
    }

    if ((ber_type & BER_TYPE_TAG_MASK) != exp_ber_type) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "?",
                  "string");
        return 0;
    }

    if ((ber_type & BER_TYPE_CONSTRUCTED)) {
        len = ber_read_length(aiv, &is_indefinite, errp);
#ifdef BER_DEBUG
        fprintf(stderr, "pos: %" PRIu64 " string len: %" PRIi64 "\n",
                aiv->cur_pos, len);
#endif

        if (*errp) {
            return 0;
        }

        if (!is_indefinite) {
            if ((*buffer) == NULL) {
                /* allocate buffer once; due to the ASN.1 overhead it
                 * will be bigger than what we need */
                *buffer = g_malloc0(len);
                if ((*buffer) == NULL) {
                    error_set(errp, QERR_OUT_OF_MEMORY);
                    return 0;
                }
                *buffer_len = len;
            }
        }
        bytes_read += ber_input_fragment(aiv, exp_ber_type,
                                          buffer, buffer_len,
                                          offset, nesting + 1, is_indefinite,
                                          aiv->cur_pos + len, name, errp);
        return bytes_read;
    }

    while (true) {
        /* not-constructed case */
        len = ber_read_length(aiv, &is_indefinite, errp);
#ifdef BER_DEBUG
        fprintf(stderr, "pos: %" PRIu64 " string len: %" PRIi64 "\n",
                aiv->cur_pos, len);
#endif
        if (is_indefinite) {
            error_set(errp, QERR_INVALID_PARAMETER,
                      "Got indefinite type length in primitve type");
            g_free(*buffer);
            *buffer = NULL;
            return 0;
        }

        if (offset + len > *buffer_len) {
            *buffer = g_realloc(*buffer, offset + len);
            *buffer_len = offset + len;
        }

        if (qemu_get_buffer(aiv->qfile,
                            &((uint8_t *)*buffer)[offset], len) != len) {
            error_set(errp, QERR_STREAM_ENDED);
            g_free(*buffer);
            *buffer = NULL;
            return 0;
        }

        offset += len;
        bytes_read += len;

        aiv->cur_pos += len;
#ifdef BER_DEBUG
        fprintf(stderr, "pos: %" PRIu64 " string: %s\n", aiv->cur_pos, *buffer);
#endif

        if (nesting == 0) {
            break;
        }

        /* indefinite length case: loop until we encounter EOC */
        if (indefinite) {
            uint8_t byte = qemu_get_byte(aiv->qfile);
            aiv->cur_pos++;

            if (byte == BER_TYPE_EOC) {
                byte = qemu_get_byte(aiv->qfile);
                aiv->cur_pos++;

                if (byte != 0) {
                    error_set(errp, QERR_INVALID_PARAMETER,
                              "ASN.1 EOC length field is invalid");
                    g_free(*buffer);
                    *buffer = NULL;
                    return 0;
                }
                return bytes_read;
            }

            if (byte != exp_ber_type) {
                error_set(errp, QERR_INVALID_PARAMETER,
                          "ASN.1 type field is wrong");
                g_free(*buffer);
                *buffer = NULL;
                return 0;
            }
            continue;
        }

        /* may never step beyond max_pos */
        assert(aiv->cur_pos <= max_pos);

        /* in definite length coding case caller tells us how far to read */
        if (aiv->cur_pos == max_pos) {
            return bytes_read;
        }

        bytes_read += ber_input_fragment(aiv, exp_ber_type,
                                          buffer, buffer_len,
                                          offset, nesting,
                                          indefinite, max_pos, name, errp);
        break;
    }
    return bytes_read;
}

static void ber_input_type_str(Visitor *v, char **obj, const char *name,
                                Error **errp)
{
    Asn1InputVisitor *aiv = to_aiv(v);
    uint32_t buffer_len = 0;

    ber_input_fragment(aiv, BER_TYPE_IA5_STRING, (uint8_t**)obj, &buffer_len,
                        0, 0, false, 0, name, errp);
}

Visitor *ber_input_get_visitor(Asn1InputVisitor *v)
{
    return &v->visitor;
}

uint64_t ber_input_get_parser_position(Asn1InputVisitor *v)
{
    return v->cur_pos;
}

void ber_input_visitor_cleanup(Asn1InputVisitor *v)
{
    g_free(v);
}

Asn1InputVisitor *ber_input_visitor_new(QEMUFile *qfile)
{
    Asn1InputVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.start_struct = ber_input_start_struct;
    v->visitor.end_struct = ber_input_end_struct;
    v->visitor.start_array = ber_input_start_array;
    v->visitor.next_array = ber_input_next_array;
    v->visitor.end_array = ber_input_end_array;
    v->visitor.type_int = ber_input_type_int;
    v->visitor.type_uint8_t = ber_input_type_uint8_t;
    v->visitor.type_uint16_t = ber_input_type_uint16_t;
    v->visitor.type_uint32_t = ber_input_type_uint32_t;
    v->visitor.type_uint64_t = ber_input_type_uint64_t;
    v->visitor.type_int8_t = ber_input_type_int8_t;
    v->visitor.type_int16_t = ber_input_type_int16_t;
    v->visitor.type_int32_t = ber_input_type_int32_t;
    v->visitor.type_int64_t = ber_input_type_int64_t;
    v->visitor.type_bool = ber_input_type_bool;
    v->visitor.type_str = ber_input_type_str;

    v->qfile = qfile;
    v->cur_pos = 0;

    return v;
}
