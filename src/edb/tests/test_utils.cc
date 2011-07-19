/*
 * test_utils.cc
 * -- useful functions for testing
 *
 *
 */

#include "test_utils.h"

void
PrintRes(ResType res)
{
  for(auto outer = res.begin(); outer != res.end(); outer++) {
    for(auto inner = outer->begin(); inner != outer->end(); inner++) {
      cerr << *inner << " | ";
    }
    cerr << endl;
  }
}

ResType *
myExecute(EDBClient * cl, string query)
{
  ResType * res;
  if (PLAIN) {
    res = cl->plain_execute(query);
  } else {
    res = cl->execute(query);
  }
  return res;
}

ResType *
myCreate(EDBClient *cl, string annotated_query, string plain_query)
{
  ResType * res;
  if (PLAIN) {
    res = cl->plain_execute(plain_query);
  } else {
    res = cl->execute(annotated_query);
  }
  return res;
}
