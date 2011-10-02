#pragma once

/*
 * Connect.h
 *
 *  Created on: Dec 1, 2010
 *      Author: raluca
 */

#include <vector>
#include <string>
#include <util/util.hh>


class DBResult {
 private:
    DBResult();

 public:
    ~DBResult();
    DBResult_native *n;

    // returns the data in the last server response
    ResType unpack();

    static DBResult *wrap(DBResult_native *);
};

class Connect {
 public:
    // dbname is the name of the local db
    Connect(std::string server, std::string user, std::string passwd,
            std::string dbname, uint port = 0);

    // returns true if execution was ok; caller must delete DBResult
    bool execute(const std::string &query, DBResult *&);
    bool execute(const std::string &query);

    // returns error message if a query caused error
    std::string getError();

    my_ulonglong last_insert_id();

    ~Connect();

 private:
#if MYSQL_S
    MYSQL * conn;
#else
    PGconn * conn;     //connection
#endif
};
