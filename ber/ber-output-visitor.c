/*
 * BER Output Visitor
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

#define CER_FRAGMENT_CHUNK_SIZE  1000

/*#define BER_DEBUG*/

typedef struct QStackEntry
{
    QEMUFile *qfile;
    QTAILQ_ENTRY(QStackEntry) node;
} QStackEntry;

typedef QTAILQ_HEAD(QStack, QStackEntry) QStack;

struct BEROutputVisitor
{
    Visitor visitor;
    QStack stack;
    QEMUFile *qfile;

    BERTypePC mode;
};

static BEROutputVisitor *to_aov(Visitor *v)
{
    return container_of(v, BEROutputVisitor, visitor);
}

static void ber_output_push(BEROutputVisitor *qov, QEMUFile *qfile,
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

static QEMUFile *ber_output_pop(BEROutputVisitor *qov)
{
    QStackEntry *e = QTAILQ_FIRST(&qov->stack);
    QEMUFile *qfile;

    QTAILQ_REMOVE(&qov->stack, e, node);
    qfile = e->qfile;
    g_free(e);

    return qfile;
}

static unsigned int ber_encode_type(uint8_t *buffer, uint32_t buflen,
                                    enum ber_type_tag ber_type,
                                    uint8_t ber_type_flags,
                                    Error **errp)
{
    unsigned int idx = 0;

    if (buflen < 1) {
        error_set(errp, QERR_BUFFER_OVERRUN);
        return 0;
    }

    if (ber_type > BER_TYPE_LONG_FORM) {
        int byte = 4;
        uint32_t mask = (0x7f << (7 * byte));
        bool do_write = false;

        buffer[0] = ber_type_flags | BER_TYPE_LONG_FORM;

        while (byte >= 0) {
            if (!do_write) {
                if ((mask & ber_type)) {
                    do_write = true;
                    if (1 + byte + 1 > buflen) {
                        error_set(errp, QERR_BUFFER_OVERRUN);
                        return 0;
                    }
                }
            }
            if (do_write) {
                buffer[1 + idx] = (ber_type >> (7 * byte)) & 0x7f;
                if (byte > 0) {
                    buffer[1 + idx] |= 0x80;
                }
                idx++;
            }
            byte--;
            mask =  (0x7f << (7 * byte));
        }
    } else {
        buffer[0] = ber_type | ber_type_flags;
    }
    return 1 + idx;
}

static unsigned int ber_encode_len(uint8_t *buffer, uint32_t buflen,
                                   uint64_t len, Error **errp)
{
    uint64_t mask = 0xFF00000000000000ULL;
    int shift =  64 - 8;
    int c = 0;

    if (len <= 0x7f && buflen >= 1) {
        buffer[0] = len;
        return 1;
    }

    while (mask && (mask & len) == 0) {
        mask >>= 8;
        shift -= 8;
    }

    while (shift >= 0) {
        if (1 + c + 1 > buflen) {
            error_set(errp, QERR_BUFFER_OVERRUN);
            return 0;
        }
        buffer[1+c] = (len >> shift);
        c++;
        shift -= 8;
    }

    buffer[0] = BER_LENGTH_LONG | c;

    return 1 + c;
}

static void ber_output_start_constructed(Visitor *v, uint32_t ber_type,
                                         Error **errp)
{
    BEROutputVisitor *aov = to_aov(v);
    uint8_t buf[20];
    unsigned int tag_bytes_written;

    switch (aov->mode) {
    case BER_TYPE_PRIMITIVE:
        ber_output_push(aov, aov->qfile, errp);
        if (error_is_set(errp)) {
            return;
        }
        aov->qfile = qemu_bufopen("w", NULL);
        if (aov->qfile == NULL) {
            error_set(errp, QERR_OUT_OF_MEMORY);
            return;
        }
        break;
    case BER_TYPE_CONSTRUCTED:
        tag_bytes_written = ber_encode_type(buf, sizeof(buf),
                                            ber_type, BER_TYPE_CONSTRUCTED,
                                            errp);
        if (error_is_set(errp)) {
            return;
        }
        buf[tag_bytes_written] = BER_LENGTH_INDEFINITE;
        if (qemu_write_bytes(aov->qfile, buf, 1 + tag_bytes_written) !=
            1 + tag_bytes_written) {
            error_set(errp, QERR_QEMUFILE_ERROR,
                      "Error while writing constructed type");
            return;
        }
    }
}

static void ber_output_constructed_ber_close(BEROutputVisitor *aov,
                                             uint32_t ber_type,
                                             Error **errp)
{
    uint8_t buf[20];
    const QEMUSizedBuffer *qsb;
    uint64_t len;
    unsigned int num_bytes, tag_bytes_written;
    QEMUFile *qfile = ber_output_pop(aov);

    tag_bytes_written = ber_encode_type(buf, sizeof(buf),
                                        ber_type, BER_TYPE_CONSTRUCTED,
                                        errp);
    if (error_is_set(errp)) {
        return;
    }

    qsb = qemu_buf_get(aov->qfile);
    len = qsb_get_length(qsb);
#ifdef BER_DEBUG
    fprintf(stderr,"constructed type (0x%02x, %p) has length %ld bytes\n",
            ber_type, aov->qfile, len);
#endif

    num_bytes = ber_encode_len(&buf[tag_bytes_written],
                               sizeof(buf) - tag_bytes_written,
                               len, errp);
    if (error_is_set(errp)) {
        return;
    }
    if (qemu_write_bytes(qfile, buf, tag_bytes_written + num_bytes) !=
        tag_bytes_written + num_bytes ||
        qemu_write_bytes(qfile, qsb_get_buffer(qsb, 0),
                         qsb_get_length(qsb)) != qsb_get_length(qsb)) {
        error_set(errp, QERR_QEMUFILE_ERROR,
                  "Error while writing buffer");
        return;
    }

    qemu_fclose(aov->qfile);
    aov->qfile = qfile;
    qemu_fflush(qfile);
}

static void ber_output_end_constructed(Visitor *v, uint32_t ber_type,
                                       Error **errp)
{
    BEROutputVisitor *aov = to_aov(v);
    uint8_t buf[20];

#ifdef BER_DEBUG
    fprintf(stderr,"end set/struct:\n");
#endif

    switch (aov->mode) {
    case BER_TYPE_PRIMITIVE:
        ber_output_constructed_ber_close(aov, ber_type, errp);
        break;

    case BER_TYPE_CONSTRUCTED:
        buf[0] = BER_TYPE_EOC;
        buf[1] = 0;
        if (qemu_write_bytes(aov->qfile, buf, 2) != 2) {
            error_set(errp, QERR_QEMUFILE_ERROR,
                      "Error while writing buffer with BER_TYPE_EOC");
            return;
        }
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

static void ber_output_fragment(Visitor *v, uint8_t ber_type,
                                uint8_t *buffer,
                                size_t buflen, Error **errp)
{
    uint32_t offset = 0;
    bool fragmented = false;
    uint32_t chunk;
    unsigned int num_bytes, type_bytes;
    uint8_t buf[20];
    uint32_t chunk_size;
    BEROutputVisitor *aov = to_aov(v);

    switch (aov->mode) {
    case BER_TYPE_CONSTRUCTED:
        /* X.690 9.2 */
        fragmented = (buflen > CER_FRAGMENT_CHUNK_SIZE);
        chunk_size = 1000;
        break;
    case BER_TYPE_PRIMITIVE:
        chunk_size = 0xffffffff;
        break;
    }

    if (fragmented) {
        ber_output_start_constructed(&aov->visitor, ber_type, errp);
        if (error_is_set(errp)) {
            return;
        }
    }

    while (offset < buflen) {
        chunk = (buflen - offset > chunk_size) ? chunk_size : buflen - offset;

        type_bytes = ber_encode_type(buf, sizeof(buf), ber_type, 0,
                                     errp);
        if (error_is_set(errp)) {
            return;
        }
        num_bytes = ber_encode_len(&buf[type_bytes], sizeof(buf) - type_bytes,
                                   chunk, errp);
        if (error_is_set(errp)) {
            return;
        }
        if (qemu_write_bytes(aov->qfile, buf, type_bytes + num_bytes) !=
            type_bytes + num_bytes ||
            qemu_write_bytes(aov->qfile, &buffer[offset], chunk) != chunk) {
            error_set(errp, QERR_QEMUFILE_ERROR,
                      "Error while writing buffer");
            return;
        }
        offset += chunk;
    }

    if (fragmented) {
        ber_output_end_constructed(&aov->visitor, ber_type, errp);
    }
}

static void ber_output_int(Visitor *v, int64_t val, uint8_t maxnumbytes,
                           Error **errp)
{
    uint8_t buf[20];
    int shift =  (maxnumbytes - 1) * 8;
    uint64_t mask = 0xFF80ULL << (shift - 8);
    bool exp_zeros;
    int c = 0;
    BEROutputVisitor *aov = to_aov(v);

#ifdef BER_DEBUG
    fprintf(stderr, "Writing int 0x%lx (signed=%d, len=%d)\n",
            val, is_signed, maxnumbytes);
#endif

    buf[0] = BER_TYPE_INTEGER;

    if (maxnumbytes > 1) {
        exp_zeros = ((mask & val) == 0) ? true : false;
        while (mask != 0xFF) {
            if (exp_zeros) {
                if ((mask & val) != 0) {
                    break;
                }
            } else {
                if ((mask & val) != mask) {
                    break;
                }
            }
            shift -= 8;
            mask >>= 8;
        }
    }

    while (shift >= 0) {
        buf[2+c] = (val >> shift);
        c++;
        shift -= 8;
    }
    buf[1] = c;

    if (qemu_write_bytes(aov->qfile, buf, 1 + 1 + c) != 1 + 1 + c) {
        error_set(errp, QERR_QEMUFILE_ERROR, "Error while writing integer");
        return;
    }
}

static void ber_output_type_int(Visitor *v, int64_t *obj, const char *name,
                                Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), errp);
}

static void ber_output_type_uint8_t(Visitor *v, uint8_t *obj,
                                    const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), errp);
}

static void ber_output_type_uint16_t(Visitor *v, uint16_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), errp);
}

static void ber_output_type_uint32_t(Visitor *v, uint32_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), errp);
}

static void ber_output_type_uint64_t(Visitor *v, uint64_t *obj,
                                     const char *name, Error **errp)
{
    ber_output_int(v, *obj, sizeof(*obj), errp);
}

static void ber_output_type_int8_t(Visitor *v, int8_t *obj,
                                   const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), errp);
}

static void ber_output_type_int16_t(Visitor *v, int16_t *obj,
                                    const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), errp);
}

static void ber_output_type_int32_t(Visitor *v, int32_t *obj,
                                    const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), errp);
}

static void ber_output_type_int64_t(Visitor *v, int64_t *obj,
                                    const char *name, Error **errp)
{
    ber_output_int(v, (int64_t)*obj, sizeof(*obj), errp);
}

static void ber_output_type_bool(Visitor *v, bool *obj, const char *name,
                                 Error **errp)
{
    BEROutputVisitor *aov = to_aov(v);
    bool b = 0;

    switch (aov->mode) {
    case BER_TYPE_PRIMITIVE:
        b = *obj;
        break;
    case BER_TYPE_CONSTRUCTED:
        b = (*obj) ? 0xff : 0;
        break;
    }
    ber_output_fragment(v, BER_TYPE_BOOLEAN, (uint8_t *)&b, sizeof(b), errp);
}

static void ber_output_type_str(Visitor *v, char **obj, const char *name,
                                Error **errp)
{
#ifdef BER_DEBUG
    fprintf(stderr, "Writing string %s, len = 0x%02x\n", *obj,
            (int)strlen(*obj));
#endif

    ber_output_fragment(v, BER_TYPE_IA5_STRING,
                        (uint8_t *)*obj, strlen(*obj), errp);
}

static void ber_output_sized_buffer(Visitor *v, uint8_t **obj,
                                    size_t size, const char *name,
                                    Error **errp)
{
    ber_output_fragment(v, BER_TYPE_OCTET_STRING,
                        *obj, size, errp);
}

void ber_output_visitor_cleanup(BEROutputVisitor *v)
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


Visitor *ber_output_get_visitor(BEROutputVisitor *v)
{
    return &v->visitor;
}

BEROutputVisitor *ber_output_visitor_new(QEMUFile *qfile,
                                         BERTypePC mode)
{
    BEROutputVisitor *v;

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
    v->visitor.type_sized_buffer = ber_output_sized_buffer;

    QTAILQ_INIT(&v->stack);
    v->qfile = qfile;
    v->mode = mode;

    return v;
}
