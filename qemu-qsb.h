#ifndef QEMU_QSB_H
#define QEMU_QSB_H

#include <stdint.h>

struct QEMUSizedBuffer {
    unsigned char *buffer;
    uint64_t size;
    uint64_t used;
};

typedef struct QEMUSizedBuffer QEMUSizedBuffer;

#endif /* QEMU_QSB_H */
