/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu-common.h"
#include "qemu_socket.h"
#include "qemu-qsb.h"
#include "hw/hw.h"

#define IO_BUF_SIZE 32768

struct QEMUFile {
    QEMUFilePutBufferFunc *put_buffer;
    QEMUFileGetBufferFunc *get_buffer;
    QEMUFileCloseFunc *close;
    QEMUFileRateLimit *rate_limit;
    QEMUFileSetRateLimit *set_rate_limit;
    QEMUFileGetRateLimit *get_rate_limit;
    void *opaque;
    int is_write;

    int64_t buf_offset; /* start of buffer when writing, end of buffer
                           when reading */
    int buf_index;
    int buf_size; /* 0 when writing */
    uint8_t buf[IO_BUF_SIZE];

    int has_error;
};

QEMUFile *qemu_fopen_ops(void *opaque, QEMUFilePutBufferFunc *put_buffer,
                         QEMUFileGetBufferFunc *get_buffer,
                         QEMUFileCloseFunc *close,
                         QEMUFileRateLimit *rate_limit,
                         QEMUFileSetRateLimit *set_rate_limit,
                         QEMUFileGetRateLimit *get_rate_limit)
{
    QEMUFile *f;

    f = g_malloc0(sizeof(QEMUFile));

    f->opaque = opaque;
    f->put_buffer = put_buffer;
    f->get_buffer = get_buffer;
    f->close = close;
    f->rate_limit = rate_limit;
    f->set_rate_limit = set_rate_limit;
    f->get_rate_limit = get_rate_limit;
    f->is_write = 0;

    return f;
}

int qemu_file_has_error(QEMUFile *f)
{
    return f->has_error;
}

void qemu_file_set_error(QEMUFile *f)
{
    f->has_error = 1;
}

void qemu_fflush(QEMUFile *f)
{
    if (!f->put_buffer)
        return;

    if (f->is_write && f->buf_index > 0) {
        int len;

        len = f->put_buffer(f->opaque, f->buf, f->buf_offset, f->buf_index);
        if (len > 0)
            f->buf_offset += f->buf_index;
        else
            f->has_error = 1;
        f->buf_index = 0;
    }
}

static void qemu_fill_buffer(QEMUFile *f)
{
    int len;

    if (!f->get_buffer)
        return;

    if (f->is_write)
        abort();

    len = f->get_buffer(f->opaque, f->buf, f->buf_offset, IO_BUF_SIZE);
    if (len > 0) {
        f->buf_index = 0;
        f->buf_size = len;
        f->buf_offset += len;
    } else if (len != -EAGAIN)
        f->has_error = 1;
}

int qemu_fclose(QEMUFile *f)
{
    int ret = 0;
    qemu_fflush(f);
    if (f->close)
        ret = f->close(f->opaque);
    g_free(f);
    return ret;
}

void qemu_file_put_notify(QEMUFile *f)
{
    f->put_buffer(f->opaque, NULL, 0, 0);
}

void qemu_put_buffer(QEMUFile *f, const uint8_t *buf, int size)
{
    int l;

    if (!f->has_error && f->is_write == 0 && f->buf_index > 0) {
        fprintf(stderr,
                "Attempted to write to buffer while read buffer is not empty\n");
        abort();
    }

    while (!f->has_error && size > 0) {
        l = IO_BUF_SIZE - f->buf_index;
        if (l > size)
            l = size;
        memcpy(f->buf + f->buf_index, buf, l);
        f->is_write = 1;
        f->buf_index += l;
        buf += l;
        size -= l;
        if (f->buf_index >= IO_BUF_SIZE)
            qemu_fflush(f);
    }
}

void qemu_put_byte(QEMUFile *f, int v)
{
    if (!f->has_error && f->is_write == 0 && f->buf_index > 0) {
        fprintf(stderr,
                "Attempted to write to buffer while read buffer is not empty\n");
        abort();
    }

    f->buf[f->buf_index++] = v;
    f->is_write = 1;
    if (f->buf_index >= IO_BUF_SIZE)
        qemu_fflush(f);
}

int qemu_get_buffer(QEMUFile *f, uint8_t *buf, int size1)
{
    int size, l;

    if (f->is_write)
        abort();

    size = size1;
    while (size > 0) {
        l = f->buf_size - f->buf_index;
        if (l == 0) {
            qemu_fill_buffer(f);
            l = f->buf_size - f->buf_index;
            if (l == 0)
                break;
        }
        if (l > size)
            l = size;
        memcpy(buf, f->buf + f->buf_index, l);
        f->buf_index += l;
        buf += l;
        size -= l;
    }
    return size1 - size;
}

int qemu_get_byte(QEMUFile *f)
{
    if (f->is_write)
        abort();

    if (f->buf_index >= f->buf_size) {
        qemu_fill_buffer(f);
        if (f->buf_index >= f->buf_size)
            return 0;
    }
    return f->buf[f->buf_index++];
}

int64_t qemu_ftell(QEMUFile *f)
{
    return f->buf_offset - f->buf_size + f->buf_index;
}

int64_t qemu_fseek(QEMUFile *f, int64_t pos, int whence)
{
    if (whence == SEEK_SET) {
        /* nothing to do */
    } else if (whence == SEEK_CUR) {
        pos += qemu_ftell(f);
    } else {
        /* SEEK_END not supported */
        return -1;
    }
    if (f->put_buffer) {
        qemu_fflush(f);
        f->buf_offset = pos;
    } else {
        f->buf_offset = pos;
        f->buf_index = 0;
        f->buf_size = 0;
    }
    return pos;
}

int qemu_peek_byte(QEMUFile *f)
{
    if (f->is_write)
        abort();

    if (f->buf_index >= f->buf_size) {
        qemu_fill_buffer(f);
        if (f->buf_index >= f->buf_size)
            return 0;
    }
    return f->buf[f->buf_index];
}

int qemu_file_rate_limit(QEMUFile *f)
{
    if (f->rate_limit)
        return f->rate_limit(f->opaque);

    return 0;
}

int64_t qemu_file_get_rate_limit(QEMUFile *f)
{
    if (f->get_rate_limit)
        return f->get_rate_limit(f->opaque);

    return 0;
}

int64_t qemu_file_set_rate_limit(QEMUFile *f, int64_t new_rate)
{
    /* any failed or completed migration keeps its state to allow probing of
     * migration data, but has no associated file anymore */
    if (f && f->set_rate_limit)
        return f->set_rate_limit(f->opaque, new_rate);

    return 0;
}

void qemu_put_be16(QEMUFile *f, unsigned int v)
{
    qemu_put_byte(f, v >> 8);
    qemu_put_byte(f, v);
}

void qemu_put_be32(QEMUFile *f, unsigned int v)
{
    qemu_put_byte(f, v >> 24);
    qemu_put_byte(f, v >> 16);
    qemu_put_byte(f, v >> 8);
    qemu_put_byte(f, v);
}

void qemu_put_be64(QEMUFile *f, uint64_t v)
{
    qemu_put_be32(f, v >> 32);
    qemu_put_be32(f, v);
}

unsigned int qemu_get_be16(QEMUFile *f)
{
    unsigned int v;
    v = qemu_get_byte(f) << 8;
    v |= qemu_get_byte(f);
    return v;
}

unsigned int qemu_get_be32(QEMUFile *f)
{
    unsigned int v;
    v = qemu_get_byte(f) << 24;
    v |= qemu_get_byte(f) << 16;
    v |= qemu_get_byte(f) << 8;
    v |= qemu_get_byte(f);
    return v;
}

uint64_t qemu_get_be64(QEMUFile *f)
{
    uint64_t v;
    v = (uint64_t)qemu_get_be32(f) << 32;
    v |= qemu_get_be32(f);
    return v;
}

typedef struct QEMUFileStdio
{
    FILE *stdio_file;
    QEMUFile *file;
} QEMUFileStdio;

typedef struct QEMUFileSocket
{
    int fd;
    QEMUFile *file;
} QEMUFileSocket;

typedef struct QEMUBuffer
{
    QEMUSizedBuffer *qsb;
    QEMUFile *file;
} QEMUBuffer;

static int socket_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    QEMUFileSocket *s = opaque;
    ssize_t len;

    do {
        len = qemu_recv(s->fd, buf, size, 0);
    } while (len == -1 && socket_error() == EINTR);

    if (len == -1)
        len = -socket_error();

    return len;
}

static int socket_close(void *opaque)
{
    QEMUFileSocket *s = opaque;
    g_free(s);
    return 0;
}

int qemu_stdio_fd(QEMUFile *f)
{
    QEMUFileStdio *p;
    int fd;

    p = (QEMUFileStdio *)f->opaque;
    fd = fileno(p->stdio_file);

    return fd;
}

static int stdio_put_buffer(void *opaque, const uint8_t *buf, int64_t pos, int size)
{
    QEMUFileStdio *s = opaque;
    return fwrite(buf, 1, size, s->stdio_file);
}

static int stdio_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    QEMUFileStdio *s = opaque;
    FILE *fp = s->stdio_file;
    int bytes;

    do {
        clearerr(fp);
        bytes = fread(buf, 1, size, fp);
    } while ((bytes == 0) && ferror(fp) && (errno == EINTR));
    return bytes;
}

static int stdio_pclose(void *opaque)
{
    QEMUFileStdio *s = opaque;
    int ret;
    ret = pclose(s->stdio_file);
    g_free(s);
    return ret;
}

static int stdio_fclose(void *opaque)
{
    QEMUFileStdio *s = opaque;
    fclose(s->stdio_file);
    g_free(s);
    return 0;
}

QEMUFile *qemu_popen(FILE *stdio_file, const char *mode)
{
    QEMUFileStdio *s;

    if (stdio_file == NULL || mode == NULL || (mode[0] != 'r' && mode[0] != 'w') || mode[1] != 0) {
        fprintf(stderr, "qemu_popen: Argument validity check failed\n");
        return NULL;
    }

    s = g_malloc0(sizeof(QEMUFileStdio));

    s->stdio_file = stdio_file;

    if(mode[0] == 'r') {
        s->file = qemu_fopen_ops(s, NULL, stdio_get_buffer, stdio_pclose, 
				 NULL, NULL, NULL);
    } else {
        s->file = qemu_fopen_ops(s, stdio_put_buffer, NULL, stdio_pclose, 
				 NULL, NULL, NULL);
    }
    return s->file;
}

QEMUFile *qemu_popen_cmd(const char *command, const char *mode)
{
    FILE *popen_file;

    popen_file = popen(command, mode);
    if(popen_file == NULL) {
        return NULL;
    }

    return qemu_popen(popen_file, mode);
}

QEMUFile *qemu_fdopen(int fd, const char *mode)
{
    QEMUFileStdio *s;

    if (mode == NULL ||
	(mode[0] != 'r' && mode[0] != 'w') ||
	mode[1] != 'b' || mode[2] != 0) {
        fprintf(stderr, "qemu_fdopen: Argument validity check failed\n");
        return NULL;
    }

    s = g_malloc0(sizeof(QEMUFileStdio));
    s->stdio_file = fdopen(fd, mode);
    if (!s->stdio_file)
        goto fail;

    if(mode[0] == 'r') {
        s->file = qemu_fopen_ops(s, NULL, stdio_get_buffer, stdio_fclose, 
				 NULL, NULL, NULL);
    } else {
        s->file = qemu_fopen_ops(s, stdio_put_buffer, NULL, stdio_fclose, 
				 NULL, NULL, NULL);
    }
    return s->file;

fail:
    g_free(s);
    return NULL;
}

QEMUFile *qemu_fopen_socket(int fd)
{
    QEMUFileSocket *s = g_malloc0(sizeof(QEMUFileSocket));

    s->fd = fd;
    s->file = qemu_fopen_ops(s, NULL, socket_get_buffer, socket_close, 
			     NULL, NULL, NULL);
    return s->file;
}

static int buf_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    QEMUBuffer *s = opaque;
    ssize_t len = qsb_get_length(s->qsb) - pos;

    if (len <= 0) {
        return 0;
    }

    if (len > size) {
        len = size;
    }
    memcpy(buf, qsb_get_buffer(s->qsb, pos), len);

    return len;
}

static int buf_put_buffer(void *opaque, const uint8_t *buf,
                          int64_t pos, int size)
{
    QEMUBuffer *s = opaque;

    return qsb_write_at(s->qsb, buf, pos, size);
}

static int buf_close(void *opaque)
{
    QEMUBuffer *s = opaque;

    qsb_free(s->qsb);

    g_free(s);

    return 0;
}

const QEMUSizedBuffer *qemu_buf_get(QEMUFile *f)
{
    QEMUBuffer *p;

    qemu_fflush(f);

    p = (QEMUBuffer *)f->opaque;

    return p->qsb;
}

QEMUFile *qemu_bufopen(const char *mode, QEMUSizedBuffer *input)
{
    QEMUBuffer *s;

    if (mode == NULL || (mode[0] != 'r' && mode[0] != 'w') || mode[1] != 0) {
        fprintf(stderr, "qemu_bufopen: Argument validity check failed\n");
        return NULL;
    }

    s = g_malloc0(sizeof(QEMUBuffer));
    if (mode[0] == 'r') {
        s->qsb = input;
    }

    if (s->qsb == NULL) {
        s->qsb = qsb_create(NULL, 0);
    }

    if(mode[0] == 'r') {
        s->file = qemu_fopen_ops(s, NULL, buf_get_buffer, buf_close,
				 NULL, NULL, NULL);
    } else {
        s->file = qemu_fopen_ops(s, buf_put_buffer, NULL, buf_close,
				 NULL, NULL, NULL);
    }
    return s->file;
}

static int file_put_buffer(void *opaque, const uint8_t *buf,
                            int64_t pos, int size)
{
    QEMUFileStdio *s = opaque;
    fseek(s->stdio_file, pos, SEEK_SET);
    return fwrite(buf, 1, size, s->stdio_file);
}

static int file_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    QEMUFileStdio *s = opaque;
    fseek(s->stdio_file, pos, SEEK_SET);
    return fread(buf, 1, size, s->stdio_file);
}

QEMUFile *qemu_fopen(const char *filename, const char *mode)
{
    QEMUFileStdio *s;

    if (mode == NULL ||
	(mode[0] != 'r' && mode[0] != 'w') ||
	mode[1] != 'b' || mode[2] != 0) {
        fprintf(stderr, "qemu_fopen: Argument validity check failed\n");
        return NULL;
    }

    s = g_malloc0(sizeof(QEMUFileStdio));

    s->stdio_file = fopen(filename, mode);
    if (!s->stdio_file)
        goto fail;
    
    if(mode[0] == 'w') {
        s->file = qemu_fopen_ops(s, file_put_buffer, NULL, stdio_fclose, 
				 NULL, NULL, NULL);
    } else {
        s->file = qemu_fopen_ops(s, NULL, file_get_buffer, stdio_fclose, 
			       NULL, NULL, NULL);
    }
    return s->file;
fail:
    g_free(s);
    return NULL;
}

int qemu_read_bytes(QEMUFile *f, uint8_t *buf, int size)
{
    if (qemu_file_has_error(f)) {
        return -1;
    }
    return qemu_get_buffer(f, buf, size);
}

int qemu_write_bytes(QEMUFile *f, const uint8_t *buf, int size)
{
    if (qemu_file_has_error(f)) {
        return -1;
    }

    qemu_put_buffer(f, buf, size);

    if (qemu_file_has_error(f)) {
        return -1;
    }

    return size;
}
