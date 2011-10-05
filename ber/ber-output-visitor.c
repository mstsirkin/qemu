/*
 * ASN.1 Output Visitor
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

#include "ber-output-visitor.h"
#include "qemu-queue.h"
#include "qemu-common.h"
#include "qerror.h"
#include "hw/hw.h"
#include "ber.h"

/* break up IA5Strings etc. into fragments of this size */
#define BER_FRAGMENT_CHUNK_SIZE  1000

/*#define BER_DEBUG*/

typedef struct QStackEntry
{
    QEMUFile *qfile;
    QTAILQ_ENTRY(QStackEntry) node;
} QStackEntry;

typedef QTAILQ_HEAD(QStack, QStackEntry) QStack;

struct Asn1OutputVisitor
{
    Visitor visitor;
    QStack stack;
    QEMUFile *qfile;

    enum QEMUAsn1Mode mode;
};

static Asn1OutputVisitor *to_aov(Visitor *v)
{
    return container_of(v, Asn1OutputVisitor, visitor);
}

static void ber_output_push(Asn1OutputVisitor *qov, QEMUFile *qfile,
                             Error **errp)
{
    QStackEntry *e = g_malloc0(sizeof(*e));

    if (e == NULL) {
        error_set(errp, QERR_OUT_OF_MEMORY);
        return;
    }

    e->qfile = qfile;
    QTAILQ_INSERT_HEAD(&qov->stack, e, node);
}

static QEMUFile *ber_output_pop(Asn1OutputVisitor *qov)
{
    QStackEntry *e = QTAILQ_FIRST(&qov->stack);
    QEMUFile *qfile;

    QTAILQ_REMOVE(&qov->stack, e, node);
    qfile = e->qfile;
    g_free(e);

    return qfile;
}

static unsigned int ber_encode_len(uint8_t *buffer, uint32_t buflen,
                                    uint64_t len, Error **errp)
{
    uint64_t mask = 0xFF00000000000000ULL;
    int shift =  64 - 8;
    int c = 0;

    if (len <= 0x7f) {
        buffer[0] = len;
        return 1;
    }

    while (mask && (mask & len) == 0) {
        mask >>= 8;
        shift -= 8;
    }

    while (shift >= 0) {
        buffer[1+c] = (len >> shift);
        c++;
        shift -= 8;
    }

    buffer[0] = BER_LENGTH_LONG | c;

    return 1 + c;
}

static void ber_output_start_constructed(Visitor *v, uint8_t ber_type,
                                          Error **errp)
{
    Asn1OutputVisitor *aov = to_aov(v);
    uint8_t buf[2];

    switch (aov->mode) {
    case BER_MODE_BER:
        ber_output_push(aov, aov->qfile, errp);
        if (*errp) {
            return;
        }
        aov->qfile = qemu_bufopen("w", NULL);
        if (aov->qfile == NULL) {
            error_set(errp, QERR_OUT_OF_MEMORY);
            return;
        }
        break;
    case BER_MODE_CER:
        buf[0] = ber_type | BER_TYPE_CONSTRUCTED;
        buf[1] = BER_LENGTH_INDEFINITE;
        qemu_put_buffer(aov->qfile, buf, 2);
    }
}

static void ber_output_constructed_ber_close(Asn1OutputVisitor *aov,
                                              uint8_t ber_type,
                                              Error **errp)
{
    uint8_t buf[10];
    const QEMUSizedBuffer *qsb;
    uint64_t len;
    unsigned int num_bytes;
    QEMUFile *qfile = ber_output_pop(aov);

    buf[0] = ber_type | BER_TYPE_CONSTRUCTED;

    qsb = qemu_buf_get(aov->qfile);
    len = qsb_get_length(qsb);
#ifdef BER_DEBUG
    fprintf(stderr,"constructed type (0x%02x, %p) has length %ld bytes\n",
            ber_type, aov->qfile, len);
#endif

    num_bytes = ber_encode_len(&buf[1], sizeof(buf) - 1, len, errp);
    if (*errp) {
        return;
    }
    qemu_put_buffer(qfile, buf, 1 + num_bytes);

    qemu_put_buffer(qfile, qsb_get_buffer(qsb, 0),
                    qsb_get_length(qsb));

    qemu_fclose(aov->qfile);
    aov->qfile = qfile;
    qemu_fflush(qfile);
}

static void ber_output_end_constructed(Visitor *v, uint8_t ber_type,
                                        Error **errp)
{
    Asn1OutputVisitor *aov = to_aov(v);
    uint8_t buf[10];

#ifdef BER_DEBUG
    fprintf(stderr,"end set/struct:\n");
#endif

    switch (aov->mode) {
    case BER_MODE_BER:
        ber_output_constructed_ber_close(aov, ber_type, errp);
        break;

    case BER_MODE_CER:
        buf[0] = 0x0;
        buf[1] = 0x0;
        qemu_put_buffer(aov->qfile, buf, 2);
        break;
    }
}

static void ber_output_start_struct(Visitor *v, void **obj, const char *kind,
                                     const char *name, size_t unused,
                                     Error **errp)
{
    ber_output_start_constructed(v, BER_TYPE_SEQUENCE, errp);
}

static void ber_output_end_struct(Visitor *v, Error **errp)
{
    ber_output_end_constructed(v, BER_TYPE_SEQUENCE, errp);
}

static void ber_output_start_array(Visitor *v, void **obj,
                                    const char *name, size_t elem_count,
                                    size_t elem_size, Error **errp)
{
    ber_output_start_constructed(v, BER_TYPE_SET, errp);
}

static void ber_output_next_array(Visitor *v, Error **errp)
{
    /* nothing to do here */
}

static void ber_output_end_array(Visitor *v, Error **errp)
{
    ber_output_end_constructed(v, BER_TYPE_SET, errp);
}

static void ber_output_int(Visitor *v, int64_t val, uint8_t maxnumbytes,
                            bool is_signed, Error **errp)
{
    uint8_t buf[20];
    int shift =  (maxnumbytes - 1) * 8;
    uint64_t mask = 0xFFULL << shift;
    uint64_t exp = 0;
    int c = 0;
    Asn1OutputVisitor *aov = to_aov(v);

#ifdef BER_DEBUG
    fprintf(stderr, "Writing int 0x%lx (signed=%d, len=%d)\n",
            val, is_signed, maxnumbytes);
#endif

    buf[0] = BER_TYPE_INTEGER;

    if (is_signed) {
        static uint64_t masks[] = {
            0xFFFFFFFF80000000ULL,
            0xFFFF8000,
            0xFF80,
        };
        uint8_t sz = sizeof(uint32_t);
        int i = 0;
        while (i < 3) {
            mask = masks[i++];
            if (val < 0) {
                exp = mask;
            }
            if (exp == (val & mask)) {
                shift = (sz - 1) * 8;
            } else {
                break;
            }
            sz /= 2;
        }
    } else {
        while (mask && (mask & val) == 0) {
            mask >>= 8;
            shift -= 8;
        }
    }

    while (shift >= 0) {
        buf[2+c] = (val >> shift);
        c++;
        shift -= 8;
    }
    buf[1] = c;

    qemu_put_buffer(aov->qfile, buf, 1+1+c);
}

static void ber_output_type_int(Visitor *v, int64_t *obj, const char *name,
                                 Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), true, errp);
}

static void ber_output_type_uint8_t(Visitor *v, uint8_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), false, errp);
}

static void ber_output_type_uint16_t(Visitor *v, uint16_t *obj,
                                      const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), false, errp);
}

static void ber_output_type_uint32_t(Visitor *v, uint32_t *obj,
                                      const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), false, errp);
}

static void ber_output_type_uint64_t(Visitor *v, uint64_t *obj,
                                      const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), false, errp);
}

static void ber_output_type_int8_t(Visitor *v, int8_t *obj,
                                    const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), true, errp);
}

static void ber_output_type_int16_t(Visitor *v, int16_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), true, errp);
}

static void ber_output_type_int32_t(Visitor *v, int32_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), true, errp);
}

static void ber_output_type_int64_t(Visitor *v, int64_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), true, errp);
}

static void ber_output_type_bool(Visitor *v, bool *obj, const char *name,
                                  Error **errp)
{
    uint8_t buf[10];
    Asn1OutputVisitor *aov = to_aov(v);

    buf[0] = BER_TYPE_BOOLEAN;
    buf[1] = 1;
    switch (aov->mode) {
    case BER_MODE_BER:
        buf[2] = *obj;
        break;
    case BER_MODE_CER:
        buf[2] = (*obj) ? 0xff : 0;
        break;
    }
    qemu_put_buffer(aov->qfile, buf, 3);
}

static void ber_output_fragment(Asn1OutputVisitor *aov, uint8_t ber_type,
                                 uint32_t chunk_size, uint8_t *buffer,
                                 uint32_t buflen, Error **errp)
{
    uint32_t offset = 0;
    bool fragmented = (buflen > chunk_size);
    uint32_t chunk;
    unsigned int num_bytes;
    uint8_t buf[10];

    if (fragmented) {
        ber_output_start_constructed(&aov->visitor, ber_type, errp);
        if (*errp) {
            return;
        }
    }

    while (offset < buflen) {
        chunk = (buflen - offset > chunk_size) ? chunk_size : buflen - offset;

        buf[0] = ber_type;
        num_bytes = ber_encode_len(&buf[1], sizeof(buf) - 1, chunk,
                                    errp);
        if (*errp) {
            return;
        }
        qemu_put_buffer(aov->qfile, buf, 1 + num_bytes);
        qemu_put_buffer(aov->qfile, &buffer[offset], chunk);
        offset += chunk;
    }

    if (fragmented) {
        ber_output_end_constructed(&aov->visitor, ber_type, errp);
    }
}

static void ber_output_type_str(Visitor *v, char **obj, const char *name,
                                 Error **errp)
{
    Asn1OutputVisitor *aov = to_aov(v);

#ifdef BER_DEBUG
    fprintf(stderr, "Writing string %s, len = 0x%02x\n", *obj,
            (int)strlen(*obj));
#endif

    ber_output_fragment(aov, BER_TYPE_IA5_STRING, BER_FRAGMENT_CHUNK_SIZE,
                         (uint8_t *)*obj, strlen(*obj), errp);
}

void ber_output_visitor_cleanup(Asn1OutputVisitor *v)
{
    QStackEntry *e, *tmp;

    QTAILQ_FOREACH_SAFE(e, &v->stack, node, tmp) {
        QTAILQ_REMOVE(&v->stack, e, node);
        if (e->qfile) {
            qemu_fclose(e->qfile);
        }
        g_free(e);
    }

    g_free(v);
}


Visitor *ber_output_get_visitor(Asn1OutputVisitor *v)
{
    return &v->visitor;
}

Asn1OutputVisitor *ber_output_visitor_new(QEMUFile *qfile,
                                           enum QEMUAsn1Mode mode)
{
    Asn1OutputVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.start_struct = ber_output_start_struct;
    v->visitor.end_struct = ber_output_end_struct;
    v->visitor.start_array = ber_output_start_array;
    v->visitor.next_array = ber_output_next_array;
    v->visitor.end_array = ber_output_end_array;
    v->visitor.type_int = ber_output_type_int;
    v->visitor.type_uint8_t = ber_output_type_uint8_t;
    v->visitor.type_uint16_t = ber_output_type_uint16_t;
    v->visitor.type_uint32_t = ber_output_type_uint32_t;
    v->visitor.type_uint64_t = ber_output_type_uint64_t;
    v->visitor.type_int8_t = ber_output_type_int8_t;
    v->visitor.type_int16_t = ber_output_type_int16_t;
    v->visitor.type_int32_t = ber_output_type_int32_t;
    v->visitor.type_int64_t = ber_output_type_int64_t;
    v->visitor.type_bool = ber_output_type_bool;
    v->visitor.type_str = ber_output_type_str;

    QTAILQ_INIT(&v->stack);
    v->qfile = qfile;
    v->mode = mode;

    return v;
}
