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

/*
 * TODO:
 *  - Write function for writing type tag to buffer
 */
#include "asn1-output-visitor.h"
#include "qemu-queue.h"
#include "qemu-common.h"
#include "hw/hw.h"
#include "asn1.h"

/* break up IA5Strings etc. into fragments of this size */
#define ASN1_FRAGMENT_CHUNK_SIZE  1000

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

static void asn1_output_push(Asn1OutputVisitor *qov, QEMUFile *qfile,
                             Error **errp)
{
    QStackEntry *e = g_malloc0(sizeof(*e));

    if (e == NULL) {
        // FIXME Set error
        return;
    }

    e->qfile = qfile;
    QTAILQ_INSERT_HEAD(&qov->stack, e, node);
}

static QEMUFile *asn1_output_pop(Asn1OutputVisitor *qov)
{
    QStackEntry *e = QTAILQ_FIRST(&qov->stack);
    QEMUFile *qfile;

    QTAILQ_REMOVE(&qov->stack, e, node);
    qfile = e->qfile;
    g_free(e);

    return qfile;
}

static unsigned int asn1_encode_len(uint8_t *buffer, uint32_t buflen,
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

static void asn1_output_start_constructed(Visitor *v, uint8_t asn1_type,
                                     void **obj, const char *kind,
                                     const char *name, size_t unused,
                                     Error **errp)
{
    Asn1OutputVisitor *aov = to_aov(v);
    uint8_t buf[2];

    switch (aov->mode) {
    case ASN1_MODE_BER:
        asn1_output_push(aov, aov->qfile, errp);
        if (*errp) {
            fprintf(stderr, "**** ERROR!\n");
            return;
        }
        aov->qfile = qemu_bufopen("w", NULL);
        if (aov->qfile == NULL) {
            // FIXME: Set error
            return;
        }
        break;
    case ASN1_MODE_CER:
        buf[0] = asn1_type;
        buf[1] = ASN1_LENGTH_INDEFINITE;
        qemu_put_buffer(aov->qfile, buf, 2);
    }
}

static void asn1_output_constructed_ber_close(Asn1OutputVisitor *aov,
                                              uint8_t asn1_type,
                                              Error **errp)
{
    uint8_t buf[10];
    const QEMUSizedBuffer *qsb;
    uint64_t len;
    unsigned int num_bytes;
    QEMUFile *qfile = asn1_output_pop(aov);

    buf[0] = asn1_type | BER_TYPE_CONSTRUCTED;

    qsb = qemu_buf_get(aov->qfile);
    len = qsb_get_length(qsb);
    fprintf(stderr,"constructed type (0x%02x, %p) has length %ld bytes\n",
            asn1_type, aov->qfile, len);

    num_bytes = asn1_encode_len(&buf[1], sizeof(buf) - 1, len, errp);
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

static void asn1_output_end_constructed(Visitor *v, uint8_t asn1_type,
                                        Error **errp)
{
    Asn1OutputVisitor *aov = to_aov(v);
    uint8_t buf[10];

    fprintf(stderr,"end set/struct:\n");

    switch (aov->mode) {
    case ASN1_MODE_BER:
        asn1_output_constructed_ber_close(aov, asn1_type, errp);
        break;

    case ASN1_MODE_CER:
        buf[0] = 0x0;
        buf[1] = 0x0;
        qemu_put_buffer(aov->qfile, buf, 2);
        break;
    }
}

static void asn1_output_start_struct(Visitor *v, void **obj, const char *kind,
                                     const char *name, size_t unused,
                                     Error **errp)
{
    asn1_output_start_constructed(v, ASN1_TYPE_SEQUENCE, obj, kind,
                                  name, unused, errp);
}

static void asn1_output_end_struct(Visitor *v, Error **errp)
{
    asn1_output_end_constructed(v, ASN1_TYPE_SEQUENCE, errp);
}

static void asn1_output_start_array(Visitor *v, void **obj,
                                    const char *name, size_t elem_count,
                                    size_t elem_size, Error **errp)
{
    asn1_output_start_constructed(v, ASN1_TYPE_SET, obj, NULL,
                                  name, elem_count * elem_size, errp);
}

static void asn1_output_next_array(Visitor *v, Error **errp)
{
    /* nothing to do here */
}

static void asn1_output_end_array(Visitor *v, Error **errp)
{
    asn1_output_end_constructed(v, ASN1_TYPE_SET, errp);
}


static void asn1_output_type_int(Visitor *v, int64_t *obj, const char *name,
                                 Error **errp)
{
    uint8_t buf[10];
    uint64_t val = *obj;
    uint64_t mask = 0xFF00000000000000ULL;
    int shift =  64 - 8;
    int c = 0;
    Asn1OutputVisitor *aov = to_aov(v);

    fprintf(stderr, "Writing int %ld\n", *obj);

    buf[0] = ASN1_TYPE_INTEGER;

    while (mask && (mask & val) == 0) {
        mask >>= 8;
        shift -= 8;
    }
    while (shift >= 0) {
        buf[2+c] = (val >> shift);
        c++;
        shift -= 8;
    }
    buf[1] = c;

    qemu_put_buffer(aov->qfile, buf, 1+1+c);
}

static void asn1_output_type_bool(Visitor *v, bool *obj, const char *name,
                                  Error **errp)
{
    uint8_t buf[10];
    Asn1OutputVisitor *aov = to_aov(v);
    fprintf(stderr, "Writing bool %d\n", *obj);

    buf[0] = ASN1_TYPE_BOOLEAN;
    buf[1] = 1;
    switch (aov->mode) {
    case ASN1_MODE_BER:
        buf[2] = *obj;
        break;
    case ASN1_MODE_CER:
        buf[2] = (*obj) ? 0xff : 0;
        break;
    }
    qemu_put_buffer(aov->qfile, buf, 3);
}

static void asn1_output_fragment(Asn1OutputVisitor *aov, uint8_t asn1_type,
                                 uint32_t chunk_size, uint8_t *buffer,
                                 uint32_t buflen, Error **errp)
{
    uint32_t offset = 0;
    bool fragmented = (buflen > chunk_size);
    uint32_t chunk;
    unsigned int num_bytes;
    uint8_t buf[10];

    switch (aov->mode) {
    case ASN1_MODE_BER:
        if (fragmented) {
            asn1_output_push(aov, aov->qfile, errp);
            if (*errp) {
                return;
            }
            aov->qfile = qemu_bufopen("w", NULL);
            if (aov->qfile == NULL) {
                // FIXME: Set error
                return;
            }
        }
        break;
    case ASN1_MODE_CER:
        if (fragmented) {
            buf[0] = asn1_type | BER_TYPE_CONSTRUCTED;
            buf[1] = ASN1_LENGTH_INDEFINITE;
            qemu_put_buffer(aov->qfile, buf, 2);
        }
        break;
    }

    while (offset < buflen) {
        chunk = (buflen - offset > chunk_size) ? chunk_size : buflen - offset;

        buf[0] = asn1_type;
        num_bytes = asn1_encode_len(&buf[1], sizeof(buf) - 1, chunk,
                                    errp);
        if (*errp) {
            return;
        }
        qemu_put_buffer(aov->qfile, buf, 1 + num_bytes);
        qemu_put_buffer(aov->qfile, &buffer[offset], chunk);
        offset += chunk;
    }

    switch (aov->mode) {
    case ASN1_MODE_BER:
        if (fragmented) {
            asn1_output_constructed_ber_close(aov, asn1_type, errp);
        }
        break;
    case ASN1_MODE_CER:
        break;
    }
}

static void asn1_output_type_str(Visitor *v, char **obj, const char *name,
                                 Error **errp)
{
    Asn1OutputVisitor *aov = to_aov(v);

    fprintf(stderr, "Writing string %s, len = 0x%02x\n", *obj,
            (int)strlen(*obj));

    asn1_output_fragment(aov, ASN1_TYPE_IA5STRING, ASN1_FRAGMENT_CHUNK_SIZE,
                         (uint8_t *)*obj, strlen(*obj), errp);
}

void asn1_output_visitor_cleanup(Asn1OutputVisitor *v)
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


Visitor *asn1_output_get_visitor(Asn1OutputVisitor *v)
{
    return &v->visitor;
}

Asn1OutputVisitor *asn1_output_visitor_new(QEMUFile *qfile,
                                           enum QEMUAsn1Mode mode)
{
    Asn1OutputVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.start_struct = asn1_output_start_struct;
    v->visitor.end_struct = asn1_output_end_struct;
    v->visitor.start_array = asn1_output_start_array;
    v->visitor.next_array = asn1_output_next_array;
    v->visitor.end_array = asn1_output_end_array;
    v->visitor.type_int = asn1_output_type_int;
    v->visitor.type_bool = asn1_output_type_bool;
    v->visitor.type_str = asn1_output_type_str;

    QTAILQ_INIT(&v->stack);
    fprintf(stderr, "top qfile=%p\n", qfile);
    v->qfile = qfile;
    v->mode = mode;

    return v;
}
