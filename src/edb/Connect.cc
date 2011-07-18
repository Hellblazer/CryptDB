/*
 * Connect.cpp
 *
 *  Created on: Dec 1, 2010
 *      Author: raluca
 */

#include "Connect.h"

Connect::Connect(string server, string user, string passwd,
                 string dbname, uint port)
{
#if MYSQL_S
    conn = mysql_init(NULL);

    /* Connect to database */
    if (!mysql_real_connect(conn, server.c_str(), user.c_str(),
                            passwd.c_str(), dbname.c_str(), port, 0, 0)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

#else /* postgres */
    string conninfo = " dbname = " + dbname;
    conn = PQconnectdb(conninfo.c_str());

    /* Check to see that the backend connection was successfully made */
    if (PQstatus(conn) != CONNECTION_OK)
    {
        fprintf(stderr, "Connection to database failed: %s",
                PQerrorMessage(conn));
        exit(1);
    }
#endif

}

bool
Connect::execute(const string &query, DBResult * & res)
{
#if MYSQL_S
    if (mysql_query(conn, query.c_str())) {
        fprintf(stderr, "mysql error: %s\n", mysql_error(conn));
        res = 0;
        return false;
    } else {
        res = DBResult::wrap(mysql_store_result(conn));
        return true;
    }
#else /* postgres */
    *res = PQexec(conn, query.c_str());

    ExecStatusType status = PQresultStatus(res->n);
    if ((status == PGRES_COMMAND_OK) || (status == PGRES_TUPLES_OK)) {
        return true;
    } else {
        cerr << "problem with " << query <<
        " error msg: " << PQerrorMessage(conn) <<
        " status " << status << "\n";
        delete *res;
        *res = 0;
        return false;
    }
#endif
}

bool
Connect::execute(const string &query)
{
    DBResult *aux;
    bool r = execute(query, aux);
    if (r)
        delete aux;
    return r;
}

string
Connect::getError()
{
#if MYSQL_S
    return mysql_error(conn);
#else
    return PQerrorMessage(conn);
#endif
}

static bool
mysql_isBinary(enum_field_types t, int charsetnr)
{
    if (((t == MYSQL_TYPE_VAR_STRING) && (charsetnr == 63)) ||
        ((t == MYSQL_TYPE_BLOB) && (charsetnr == 63)))
    {
        return true;
    } else {
        return false;
    }
}

uint64_t
Connect::last_insert_id()
{
    return mysql_insert_id(conn);
}

Connect::~Connect()
{
#if MYSQL_S
    mysql_close(conn);
#else /*postgres */
    PQfinish(conn);
#endif
}

DBResult::DBResult()
{
}

DBResult *
DBResult::wrap(DBResult_native *n)
{
    DBResult *r = new DBResult();
    r->n = n;
    return r;
}

DBResult::~DBResult()
{
#if MYSQL_S
    mysql_free_result(n);
#else
    PQclear(n);
#endif
}

// returns the data in the last server response
// TODO: to optimize return pointer to avoid overcopying large result sets?
ResType *
DBResult::unpack()
{
#if MYSQL_S

    cerr << "a\n";
    if (n == NULL) {
        return new ResType();
    }
    cerr << "b\n";
    int rows = mysql_num_rows(n);
    int cols  = -1;
    if (rows > 0) {
        cols = mysql_num_fields(n);
    } else {
        return new ResType();
    }
    cerr << "c\n";

    ResType *res = new vector<vector<string> >();

    cerr << "d\n";

    // first row contains names
    res->push_back(vector<string>(cols));

    cerr << "e\n";

    bool binFlags[cols];
    for (int j = 0;; j++) {
        MYSQL_FIELD *field = mysql_fetch_field(n);
        if (!field)
            break;

        binFlags[j] = mysql_isBinary(field->type, field->charsetnr);
        (*res)[0][j] = string(field->name);
    }

    for (int index = 0;; index++) {
        MYSQL_ROW row = mysql_fetch_row(n);
        if (!row)
            break;
        unsigned long *lengths = mysql_fetch_lengths(n);

        res->push_back(vector<string>(cols));

        for (int j = 0; j < cols; j++) {
            if (binFlags[j] && !DECRYPTFIRST) {
                (*res)[index+1][j] = marshallBinary(string(row[j], lengths[j]));
            } else {
                if (row[j] == NULL) {
                    /*
                     * XXX why are we losing NULLs?
                     */
                    (*res)[index+1][j] = "";
                } else {
                    (*res)[index+1][j] = string(row[j], lengths[j]);
                }
            }
        }
    }

    return res;

#else /* postgres */

    unsigned int cols = PQnfields(n);
    unsigned int rows = PQntuples(n);

    ResType *res = new vector<vector<string> >[rows+1];

    // first, fill up first row with names
    (*res)[0] = new vector<string>[cols];
    for (uint i = 0; i < cols; i++)
        (*res)[0][i] = string(PQfname(dbAnswer, i));

    // fill up values
    for (uint i = 0; i < rows; i++)
        for (uint j = 0; j < cols; j++)
            (*res)[i+1][j] = string(PQgetvalue(n, i, j));

    return res;
#endif

}

