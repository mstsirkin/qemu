/*
 * ASN.1 Common functions
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Stefan Berger     <stefanb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include <stdint.h>

#include "asn1.h"

#define ASN1_TYPES_MAX 0x1e

static const char *asn1_type_names[ASN1_TYPES_MAX] = {
    "ASN1_TYPE_EOC",
    "ASN1_TYPE_BOOLEAN",
    "ASN1_TYPE_INTEGER",
    "ASN1_TYPE_BIT_STRING",
    "ASN1_TYPE_OCTET_STRING",
    "ASN1_TYPE_NULL",
    "ASN1_TYPE_OBJECT_ID",
    "ASN1_TYPE_OBJECT_DESC",
    "ASN1_TYPE_EXTERNAL",
    "ASN1_TYPE_REAL",
    "ASN1_TYPE_ENUMERATED",
    "ASN1_TYPE_EMBEDDED",
    "ASN1_TYPE_UTF8_STRING",
    "ASN1_TYPE_RELATIVE_OID",
    "ASN1_TYPE_UNUSED_0xE",
    "ASN1_TYPE_UNUSED_0xF",
    "ASN1_TYPE_SEQUENCE",
    "ASN1_TYPE_SET",
    "ASN1_TYPE_NUMERIC_STRING",
    "ASN1_TYPE_PRINTABLE_STRING",
    "ASN1_TYPE_T61STRING",
    "ASN1_TYPE_VIDEOTEX_STRING"
    "ASN1_TYPE_IA5_STRING",
    "ASN1_TYPE_UTCTIME",
    "ASN1_TYPE_GENERALIZED_TIME",
    "ASN1_TYPE_GRAPHIC_STRING",
    "ASN1_TYPE_VISIBLE_STRING",
    "ASN1_TYPE_GENERAL_STRING",
    "ASN1_TYPE_UNIVERSAL_STRING",
    "ASN1_TYPE_CHARACTER_STRING"
    "ASN1_TYPE_BMP_STRING",
    "ASN1_TYPE_LONG_FORM",
};

const char *asn1_type_to_str(uint8_t asn1_type)
{
    asn1_type = (asn1_type & 0x1f);
    if (asn1_type > ASN1_TYPES_MAX) {
        return "Unknown ASN1 type";
    }
    return asn1_type_names[asn1_type];
}
