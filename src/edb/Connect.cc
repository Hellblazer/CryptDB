/*
 * Connect.cpp
 *
 *  Created on: Dec 1, 2010
 *      Author: raluca
 */

#include <stdexcept>
#include <edb/Connect.h>
#include <edb/cryptdb_log.h>

Connect::Connect(string server, string user, string passwd,
                 string dbname, uint port)
{
#if MYSQL_S
    conn = mysql_init(NULL);

    /* Make sure we always connect via TCP, and not via Unix domain sockets */
    uint proto = MYSQL_PROTOCOL_TCP;
    mysql_options(conn, MYSQL_OPT_PROTOCOL, &proto);

    /* Connect to the real server even if linked against embedded libmysqld */
    mysql_options(conn, MYSQL_OPT_USE_REMOTE_CONNECTION, 0);

    /* Connect to database */
    if (!mysql_real_connect(conn, server.c_str(), user.c_str(),
                            passwd.c_str(), dbname.c_str(), port, 0, 0)) {
    	LOG(warn) << "connecting to server " << server
                  << " user " << user
                  << " pwd " << passwd
                  << " dbname " << dbname
                  << " port " << port;
        LOG(warn) << "mysql_real_connect: " << mysql_error(conn);
        throw runtime_error("cannot connect");
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
        LOG(warn) << "mysql_query: " << mysql_error(conn);
        LOG(warn) << "on query: " << query;
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


my_ulonglong
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
ResType
DBResult::unpack()
{
#if MYSQL_S
    if (n == NULL)
        return ResType();

    size_t rows = (size_t)mysql_num_rows(n);
    int cols  = -1;
    if (rows > 0) {
        cols = mysql_num_fields(n);
    } else {
        return ResType();
    }

    ResType res;

    for (int j = 0;; j++) {
        MYSQL_FIELD *field = mysql_fetch_field(n);
        if (!field)
            break;

        res.names.push_back(field->name);
        res.types.push_back(field->type);
    }

    for (int index = 0;; index++) {
        MYSQL_ROW row = mysql_fetch_row(n);
        if (!row)
            break;
        unsigned long *lengths = mysql_fetch_lengths(n);

        vector<SqlItem> resrow;

        for (int j = 0; j < cols; j++) {
            SqlItem item;
            if (row[j] == NULL) {
                item.null = true;
            } else {
                item.null = false;
                item.type = res.types[j];
                item.data = string(row[j], lengths[j]);
            }
            resrow.push_back(item);
        }

        res.rows.push_back(resrow);
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

