#ifndef BER_BER_H
#define BER_BER_H

/* This is a subset of BER for QEMU use. */
/* QEMU will use the DER encoding always with one extension from
 * CER: SET and SEQUENCE types can have indefinite-length encoding
 * if the encoding is not all immediately available.
 *
 * We assume that SET encodings can be available or not available,
 * and that SEQUENCE encodings are available unless a SEQUENCE includes
 * a non-available SET.
 *
 * The last is an extension to allow an arbitrarily large SET
 * to be produced online without knowing the length in advance.
 *
 * All types used shall be universal, with explicit tagging, to simplify
 * use by external tools.
 */

typedef enum ber_type_class {
    BER_TYPE_CLASS_UNIVERSAL = 0x0 << 7,
    BER_TYPE_CLASS_APPLICATION = 0x1 << 6,
    BER_TYPE_CLASS_CONTENT_SPECIFIC = 0x2 << 6,
    BER_TYPE_CLASS_PRIVATE = 0x3 << 6,
    BER_TYPE_CLASS_MASK = 0x3 << 6 /* Mask to get class */
} BERTypeClass;

/* P/C bit */
typedef enum ber_type_p_c {
    BER_TYPE_PRIMITIVE = (0x0 << 5),
    BER_TYPE_CONSTRUCTED = (0x1 << 5),
    BER_TYPE_P_C_MASK = (0x1 << 5) /* Mask to get P/C bit */
} BERTypePC;

typedef enum ber_type_tag {
    BER_TYPE_EOC              /*  P        0       0*/,
    BER_TYPE_BOOLEAN          /*  P        1       1*/,
    BER_TYPE_INTEGER          /*  P        2       2*/,
    BER_TYPE_BIT_STRING       /*  P/C      3       3*/,
    BER_TYPE_OCTET_STRING     /*  P/C      4       4*/,
    BER_TYPE_NULL             /*  P        5       5*/,
    BER_TYPE_OBJECT_ID        /*  P        6       6*/,
    BER_TYPE_OBJECT_DESC      /*  P        7       7*/,
    BER_TYPE_EXTERNAL         /*  C        8       8*/,
    BER_TYPE_REAL             /*  P        9       9*/,
    BER_TYPE_ENUMERATED       /*  P        10      A*/,
    BER_TYPE_EMBEDDED         /*  C        11      B*/,
    BER_TYPE_UTF8_STRING      /*  P/C      12      C*/,
    BER_TYPE_RELATIVE_OID     /*  P        13      D*/,
    BER_TYPE_UNUSED_0xE       /*                    */,
    BER_TYPE_UNUSED_0xF       /*                    */,
    BER_TYPE_SEQUENCE         /*  C        16      10*/,
    BER_TYPE_SET              /*  C        17      11*/,
    BER_TYPE_NUMERIC_STRING   /*  P/C      18      12*/,
    BER_TYPE_PRINTABLE_STRING /*  P/C      19      13*/,
    BER_TYPE_T61STRING        /*  P/C      20      14*/,
    BER_TYPE_VIDEOTEX_STRING  /*  P/C      21      15*/,
    BER_TYPE_IA5_STRING       /*  P/C      22      16*/,
    BER_TYPE_UTCTIME          /*  P/C      23      17*/,
    BER_TYPE_GENERALIZED_TIME /*  P/C      24      18*/,
    BER_TYPE_GRAPHIC_STRING   /*  P/C      25      19*/,
    BER_TYPE_VISIBLE_STRING   /*  P/C      26      1A*/,
    BER_TYPE_GENERAL_STRING   /*  P/C      27      1B*/,
    BER_TYPE_UNIVERSAL_STRING /*  P/C      28      1C*/,
    BER_TYPE_CHARACTER_STRING /*  P/C      29      1D*/,
    BER_TYPE_BMP_STRING       /*  P/C      30      1E*/,
    BER_TYPE_LONG_FORM        /*  -        31      1F*/,
    BER_TYPE_TAG_MASK = 0x1f /* Mask to get tag */
} BERTypeTag;

typedef enum ber_length {
    /* Special length values */
    BER_LENGTH_INDEFINITE = (0x1 << 7),
    BER_LENGTH_RESERVED = 0xFF,
    /* Anything else is either short or long */
    BER_LENGTH_SHORT = (0x0 << 7),
    BER_LENGTH_LONG = (0x1 << 7),
    BER_LENGTH_SHORT_LONG_MASK = (0x1 << 7),
    BER_LENGTH_MASK = 0x7F,
} BERLength;

const char *ber_type_to_str(uint8_t ber_type);

#endif /* BER_BER_H */
