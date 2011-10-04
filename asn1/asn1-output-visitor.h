/*
 * Output Visitor
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

#ifndef ASN1_OUTPUT_VISITOR_H
#define ASN1_OUTPUT_VISITOR_H

#include "qapi/qapi-visit-core.h"
#include "asn1.h"

typedef struct Asn1OutputVisitor Asn1OutputVisitor;

Asn1OutputVisitor *asn1_output_visitor_new(QEMUFile *, enum QEMUAsn1Mode mode);
void asn1_output_visitor_cleanup(Asn1OutputVisitor *v);

Visitor *asn1_output_get_visitor(Asn1OutputVisitor *v);

#endif
