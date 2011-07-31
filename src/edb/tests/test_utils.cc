/*
 * test_utils.cc
 * -- useful functions for testing
 *
 *
 */

#include "test_utils.h"

void
PrintRes(const ResType &res)
{
    for (auto i = res.names.begin(); i != res.names.end(); i++)
        cerr << *i << " | ";
    cerr << endl;
    for (auto outer = res.rows.begin(); outer != res.rows.end(); outer++) {
        for (auto inner = outer->begin(); inner != outer->end(); inner++)
            cerr << *inner << " | ";
        cerr << endl;
    }
}

ResType
myExecute(EDBClient * cl, string query)
{
    if (PLAIN)
        return cl->plain_execute(query);
    else
        return cl->execute(query);
}

ResType
myCreate(EDBClient *cl, string annotated_query, string plain_query)
{
    if (PLAIN)
        return cl->plain_execute(plain_query);
    else
        return cl->execute(annotated_query);
}
