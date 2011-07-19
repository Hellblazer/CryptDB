/*
 * test_utils.h
 *
 * Created on: Jul 18. 2011
 *   Author: cat_red
 */

#include "EDBClient.h"

#define PLAIN 0
#define STOP_IF_FAIL 1

#ifndef TESTUTILS_H_
#define TESTUTILS_H_

void PrintRes(ResType res);

template <int N> ResType convert(string rows[][N], int num_rows);

ResType * myExecute(EDBClient * cl, string query);

ResType * myCreate(EDBClient * cl, string annotated_query, string plain_query);

#endif /* TESTUTILS_H_ */
