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

class Connect {
public:

	//dbname is the name of the local db
	Connect(string server, string user, string psswd, string dbname, string port = "");

   //returns true if execution was ok
	bool execute(const char * query, DBResult * &);
    bool execute(const char * query);

    //returns error message if a query caused error
	const char * getError();

	string last_insert_id();

	//returns the data in the last server response
	static ResType * unpack(DBResult *);

	void finish();

	virtual ~Connect();

#if MYSQL_S
	MYSQL * conn;
#else
	PGconn * conn; //connection
#endif

private:


};

#endif /* CONNECT_H_ */
