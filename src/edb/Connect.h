/*
 * Connect.h
 *
 *  Created on: Dec 1, 2010
 *      Author: raluca
 */

#ifndef CONNECT_H_
#define CONNECT_H_


#include <vector>
#include <string>
#include "util.h"


using namespace std;

class DBResult {
 private:
	DBResult();

 public:
	~DBResult();
	DBResult_native *n;

	// returns the data in the last server response
	ResType *unpack();

	static DBResult *wrap(DBResult_native *);
};

class Connect {
 public:
	// dbname is the name of the local db
	Connect(string server, string user, string passwd,
		string dbname, uint port = 0);

	// returns true if execution was ok; caller must delete DBResult
	bool execute(const char * query, DBResult *&);
	bool execute(const char * query);

	// returns error message if a query caused error
	const char * getError();

	uint64_t last_insert_id();

	~Connect();

 private:
#if MYSQL_S
	MYSQL * conn;
#else
	PGconn * conn; //connection
#endif
};

#endif /* CONNECT_H_ */
