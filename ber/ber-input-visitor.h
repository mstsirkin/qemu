/*
 * Input Visitor
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

#ifndef BER_INPUT_VISITOR_H
#define BER_INPUT_VISITOR_H

#include "qapi/qapi-visit-core.h"

typedef struct Asn1InputVisitor Asn1InputVisitor;

Asn1InputVisitor *ber_input_visitor_new(QEMUFile *);
void ber_input_visitor_cleanup(Asn1InputVisitor *v);
uint64_t ber_input_get_parser_position(Asn1InputVisitor *v);

Visitor *ber_input_get_visitor(Asn1InputVisitor *v);

#endif
