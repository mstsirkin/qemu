#include "qemu-common.h"
#include "qemu-qsb.h"

QEMUSizedBuffer *qsb_create(const uint8_t *buffer, uint64_t len)
{
     QEMUSizedBuffer *qsb;
     uint64_t alloc_len;

     alloc_len = (len > 1024) ? len : 1024;

     qsb = g_malloc0(sizeof(*qsb));

     qsb->buffer = g_malloc(alloc_len);
     if (!qsb->buffer) {
         return NULL;
     }
     qsb->size = alloc_len;

     if (buffer) {
         memcpy(qsb->buffer, buffer, len);
         qsb->used = len;
     }

     return qsb;
}

void qsb_free(QEMUSizedBuffer *qsb)
{
    g_free(qsb->buffer);
    g_free(qsb);
}

uint64_t qsb_get_length(const QEMUSizedBuffer *qsb)
{
    return qsb->used;
}

const unsigned char *qsb_get_buffer(const QEMUSizedBuffer *qsb, int64_t pos)
{
    if (pos < qsb->used) {
        return &qsb->buffer[pos];
    }
    return NULL;
}

int qsb_write_at(QEMUSizedBuffer *qsb, const uint8_t *buf,
                 int64_t pos, int size)
{
    if (pos + size > qsb->size) {
        qsb->buffer = g_realloc(qsb->buffer, pos + size + 1024);
        if (qsb->buffer == NULL) {
            return -ENOMEM;
        }
        qsb->size = pos + size;
    }
    memcpy(&qsb->buffer[pos], buf, size);
    if (pos + size > qsb->used) {
        qsb->used = pos + size;
    }

    return size;
}

int qsb_append_qsb(QEMUSizedBuffer *dest, const QEMUSizedBuffer *src)
{
    return qsb_write_at(dest, qsb_get_buffer(src, 0),
                        qsb_get_length(dest), qsb_get_length(src));
}

int qsb_append(QEMUSizedBuffer *dest, const uint8_t *buf, uint64_t len)
{
    return qsb_write_at(dest, buf,
                        qsb_get_length(dest), len);
}

QEMUSizedBuffer *qsb_clone(const QEMUSizedBuffer *in)
{
    return qsb_create(qsb_get_buffer(in, 0),
                      qsb_get_length(in));
}
