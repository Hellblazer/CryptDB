/*
 * MultiPrincipal.h
 *
 * Performs the high level multi-principal work: parsing and interaction with key access.
 *
 */

#ifndef MULTIPRINC_H_
#define MULTIPRINC_H_

#include "util.h"
#include "AccessManager.h"
#include "Translator.h"


class MultiPrinc {
public:
	MultiPrinc(Connect * conn);

	virtual ~MultiPrinc();

	/***  CREATE TABLES tasks ***/

	/*
	 *
	 * processes access link
	 * sets wordsIt to next field to process in Create
	 * updates encforMap and accMan
	 * sets encryptfield
	 */
	void processAnnotation(list<string>::iterator & wordsIt, list<string> & words, string tablename, string currentField, bool & encryptfield, map<string, TableMetadata *> & tm);


	int commitAnnotations();


	/*** LOGIN tasks ***/

	bool isActiveUsers(const char * query);

	bool checkPsswd(command comm, list<string> & words);

	/** FILTERS "WHERE" tasks **/

	//returns a map from encrypted field name to the value of field for which it is encrypted e.g. text - 5 (val of gid)
	void getEncForFromFilter(command comm, list<string> query, TMKM & tmkm, QueryMeta & qm, map<string, TableMetadata *> & tableMetaMap);

	/*** SELECT taks ***/

	// returns any additional fields that need to be requested from the DB when table.field is requested
	string selectEncFor(string table, string field, QueryMeta & qm,  TMKM & tmkm, TableMetadata * tm, FieldMetadata * fm);

	void prepareSelect(list<string> & words, TMKM & tmkm, QueryMeta & qm, map<string, TableMetadata *> & tm);

	// fills tmkm.encForReturned and decides if the next field was added by us and should not be returned to the user
	void processReturnedField(unsigned int index, string fullname, onion o, TMKM & tmkm, bool & ignore);


	bool checkPredicate(string hasaccess, map<string, string> & vals);

	/*** INSERT tasks ***/

	//wordsIt points to the first value
	void insertRelations(const list<string> & values, string table, list<string> fields, TMKM & tmkm);

	/*** OTHER ***/

	bool isPrincipal(string fullname);

	// -- Determines which key to use for a field
	// -- They return null if the set of active users cannot decrypt current field
	// -- the key is to be used for a query
	string get_key(string fieldName, TMKM & tmkm);

	// -- Determines which key to use for a field
	// -- They return null if the set of active users cannot decrypt current field
	// -- the key is to be used for a result set
	string get_key(string fieldName, TMKM & tmkm,  const vector<string>  & res);

private:

	Connect * conn;
	MultiKeyMeta mkm;
	KeyAccess * accMan;


};

#endif /* MULTIPRINC_H_ */
