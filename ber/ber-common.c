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

#include "ber.h"

#define BER_TYPES_MAX 0x1e

static const char *ber_type_names[BER_TYPES_MAX] = {
    "BER_TYPE_EOC",
    "BER_TYPE_BOOLEAN",
    "BER_TYPE_INTEGER",
    "BER_TYPE_BIT_STRING",
    "BER_TYPE_OCTET_STRING",
    "BER_TYPE_NULL",
    "BER_TYPE_OBJECT_ID",
    "BER_TYPE_OBJECT_DESC",
    "BER_TYPE_EXTERNAL",
    "BER_TYPE_REAL",
    "BER_TYPE_ENUMERATED",
    "BER_TYPE_EMBEDDED",
    "BER_TYPE_UTF8_STRING",
    "BER_TYPE_RELATIVE_OID",
    "BER_TYPE_UNUSED_0xE",
    "BER_TYPE_UNUSED_0xF",
    "BER_TYPE_SEQUENCE",
    "BER_TYPE_SET",
    "BER_TYPE_NUMERIC_STRING",
    "BER_TYPE_PRINTABLE_STRING",
    "BER_TYPE_T61STRING",
    "BER_TYPE_VIDEOTEX_STRING"
    "BER_TYPE_IA5_STRING",
    "BER_TYPE_UTCTIME",
    "BER_TYPE_GENERALIZED_TIME",
    "BER_TYPE_GRAPHIC_STRING",
    "BER_TYPE_VISIBLE_STRING",
    "BER_TYPE_GENERAL_STRING",
    "BER_TYPE_UNIVERSAL_STRING",
    "BER_TYPE_CHARACTER_STRING"
    "BER_TYPE_BMP_STRING",
    "BER_TYPE_LONG_FORM",
};

const char *ber_type_to_str(uint8_t ber_type)
{
    ber_type = (ber_type & 0x1f);
    if (ber_type > BER_TYPES_MAX) {
        return "Unknown BER type";
    }
    return ber_type_names[ber_type];
}
