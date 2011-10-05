/*
 * BER Input Visitor header
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

typedef struct BERInputVisitor BERInputVisitor;

BERInputVisitor *ber_input_visitor_new(QEMUFile *);
void ber_input_visitor_cleanup(BERInputVisitor *v);
uint64_t ber_input_get_parser_position(BERInputVisitor *v);

Visitor *ber_input_get_visitor(BERInputVisitor *v);

#endif
