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
	conn = PQconnectdb(getCStr(conninfo));

	/* Check to see that the backend connection was successfully made */
	if (PQstatus(conn) != CONNECTION_OK)
	{
		fprintf(stderr, "Connection to database failed: %s",
				PQerrorMessage(conn));
		exit(1);

	}


#endif

}


//returns true if execution was ok
bool Connect::execute(const char * query, DBResult * & res) {

#if MYSQL_S

	if (mysql_query(conn, query)) {
			fprintf(stderr, "error %s\n", mysql_error(conn));
			res = NULL;
			return false;
	} else {

		res = mysql_store_result(conn);
		return true;
	}

#else /* postgres */

        res = PQexec(conn, query);

        ExecStatusType status = PQresultStatus(res);

		if ((status == PGRES_COMMAND_OK) || (status == PGRES_TUPLES_OK)) {
				return true;
		} else {
				cerr << "problem with " << query << " error msg: " << PQerrorMessage(conn) << " status " << status << "\n";
				return false;
		}

#endif

}

bool Connect::execute(const char * query) {
	DBResult * aux;
	return execute(query, aux);
}
const char * Connect::getError() {

#if MYSQL_S
	return mysql_error(conn);
#else
	return PQerrorMessage(conn);
#endif

}


bool mysql_isBinary(enum_field_types t, int charsetnr) {
	if (((t == MYSQL_TYPE_VAR_STRING) && (charsetnr == 63)) || ((t == MYSQL_TYPE_BLOB) && (charsetnr == 63))) {
		return true;
	} else {
		return false;
	}
}

string Connect::last_insert_id() {
	return marshallVal((uint64_t) mysql_insert_id(conn));
}
//returns the data in the last server response
//TODO: to optimize return pointer to avoid overcopying large result sets?
ResType * Connect::unpack(DBResult * lastReply){

#if MYSQL_S

	if (!lastReply) {
		return new vector<vector<string> >();
	}


	int cols = mysql_num_fields(lastReply);

	int rows =  mysql_num_rows(lastReply);


	vector<vector<string> > * res = new vector<vector<string> >(rows+1);

	if (rows == 0) {
		res->at(0) = vector<string>(cols);
		MYSQL_FIELD * field;
		int j = 0;
		while ((field = mysql_fetch_field(lastReply))) {
			res->at(0)[j] = string(field->name);
			j++;
		}

		assert_s(j == cols, "less fields than cols \n");

		return res;
	}

	//cerr << "result has " << cols << "cols and " << rows << " rows \n";


	bool binFlags[cols];

	//first row contains names
	res->at(0) = vector<string>(cols);
	int index= 0;
	MYSQL_ROW row;
	unsigned long *lengths;
	while ((row = mysql_fetch_row(lastReply)) != NULL) {
		lengths = mysql_fetch_lengths(lastReply);
		if (index == 0) {
			MYSQL_FIELD * field;
			int j = 0;
			while ((field = mysql_fetch_field(lastReply))) {
				binFlags[j] = mysql_isBinary(field->type, field->charsetnr);
				(*res)[0][j] =  string(field->name);

				j++;
			}
		}

		index++;
		(*res)[index] = vector<string>(cols);
		// long unsigned int * lengths = mysql_fetch_lengths(dbAnswer);
		for (int j = 0 ; j < cols; j++) {

			if (binFlags[j] && (!DECRYPTFIRST)) {
				(*res)[index][j] = marshallBinary((unsigned char*)row[j], lengths[j]); //TODO: possible performance loss due to marshall and unmarshall
			} else {

				if (row[j] == NULL) {
					(*res)[index][j] = "";
				} else {
					(*res)[index][j] = string(row[j]);
				}

			}

		}
	}



	return res;

#else /* postgres */


   unsigned int cols = PQnfields(lastReply);
   unsigned int rows = PQntuples(lastReply);

   if (rows == 0) {
	   return new ResType();
   }

   vector<vector<string> > res = new vector<vector<string> >[rows+1];

   //first, fill up first row with names
   res[0] = new vector[cols];
   for (unsigned int i = 0; i < cols; i++) {
		res[0][i] = string(PQfname(dbAnswer, i));
	}

   //fillup values
   for (unsigned int i = 0; i < rows; i++) {
	   for (unsigned int j = 0; j < cols; j++) {
		   res[i+1][j] = string(PQgetvalue(lastReply, i,j));
	   }
   }

   return res;

#endif

}



void Connect::finish() {
#if MYSQL_S
	mysql_close(conn);
#else /*postgres */
	PQfinish(conn);
#endif

}

Connect::~Connect() {

}
