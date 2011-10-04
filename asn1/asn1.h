#ifndef ASN1_ASN1_H
#define ASN1_ASN1_H

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

typedef enum asn1_type_class {
    ASN1_TYPE_CLASS_UNIVERSAL = 0x0 << 7,
    ASN1_TYPE_CLASS_APPLICATION = 0x1 << 6,
    ASN1_TYPE_CLASS_CONTENT_SPECIFIC = 0x2 << 6,
    ASN1_TYPE_CLASS_PRIVATE = 0x3 << 6,
    ASN1_TYPE_CLASS_MASK = 0x3 << 6 /* Mask to get class */
} Asn1TypeClass;

/* P/C bit */
typedef enum asn1_type_p_c {
    ASN1_TYPE_PRIMITIVE = (0x0 << 5),
    ASN1_TYPE_CONSTRUCTED = (0x1 << 5),
    ASN1_TYPE_P_C_MASK = (0x1 << 5) /* Mask to get P/C bit */
} Asn1TypePC;

typedef enum asn1_type_tag {
    ASN1_TYPE_EOC              /*  P        0       0*/,
    ASN1_TYPE_BOOLEAN          /*  P        1       1*/,
    ASN1_TYPE_INTEGER          /*  P        2       2*/,
    ASN1_TYPE_BIT_STRING       /*  P/C      3       3*/,
    ASN1_TYPE_OCTET_STRING     /*  P/C      4       4*/,
    ASN1_TYPE_NULL             /*  P        5       5*/,
    ASN1_TYPE_OBJECT_ID        /*  P        6       6*/,
    ASN1_TYPE_OBJECT_DESC      /*  P        7       7*/,
    ASN1_TYPE_EXTERNAL         /*  C        8       8*/,
    ASN1_TYPE_REAL             /*  P        9       9*/,
    ASN1_TYPE_ENUMERATED       /*  P        10      A*/,
    ASN1_TYPE_EMBEDDED         /*  C        11      B*/,
    ASN1_TYPE_UTF8_STRING      /*  P/C      12      C*/,
    ASN1_TYPE_RELATIVE_OID     /*  P        13      D*/,
    ASN1_TYPE_UNUSED_0xE       /*                    */,
    ASN1_TYPE_UNUSED_0xF       /*                    */,
    ASN1_TYPE_SEQUENCE         /*  C        16      10*/,
    ASN1_TYPE_SET              /*  C        17      11*/,
    ASN1_TYPE_NUMERIC_STRING   /*  P/C      18      12*/,
    ASN1_TYPE_PRINTABLE_STRING /*  P/C      19      13*/,
    ASN1_TYPE_T61STRING        /*  P/C      20      14*/,
    ASN1_TYPE_VIDEOTEX_STRING  /*  P/C      21      15*/,
    ASN1_TYPE_IA5_STRING       /*  P/C      22      16*/,
    ASN1_TYPE_UTCTIME          /*  P/C      23      17*/,
    ASN1_TYPE_GENERALIZED_TIME /*  P/C      24      18*/,
    ASN1_TYPE_GRAPHIC_STRING   /*  P/C      25      19*/,
    ASN1_TYPE_VISIBLE_STRING   /*  P/C      26      1A*/,
    ASN1_TYPE_GENERAL_STRING   /*  P/C      27      1B*/,
    ASN1_TYPE_UNIVERSAL_STRING /*  P/C      28      1C*/,
    ASN1_TYPE_CHARACTER_STRING /*  P/C      29      1D*/,
    ASN1_TYPE_BMP_STRING       /*  P/C      30      1E*/,
    ASN1_TYPE_LONG_FORM        /*  -        31      1F*/,
    ASN1_TYPE_TAG_MASK = 0x1f /* Mask to get tag */
} Asn1TypeTag;

typedef enum asn1_length {
    /* Special length values */
    ASN1_LENGTH_INDEFINITE = (0x1 << 7),
    ASN1_LENGTH_RESERVED = 0xFF,
    /* Anything else is either short or long */
    ASN1_LENGTH_SHORT = (0x0 << 7),
    ASN1_LENGTH_LONG = (0x1 << 7),
    ASN1_LENGTH_SHORT_LONG_MASK = (0x1 << 7),
    ASN1_LENGTH_MASK = 0x7F,
} Asn1Length;

enum QEMUAsn1Mode {
  ASN1_MODE_BER = 1,
  ASN1_MODE_CER = 2,
};

const char *asn1_type_to_str(uint8_t asn1_type);

#endif /* ASN1_ASN1_H */
