#ifndef _EDBCLIENT_H
#define _EDBCLIENT_H


#include "Translator.h"
#include "Connect.h"
#include <iostream>
#include <fstream>

#include "MultiPrinc.h"

using namespace std;

class EDBClient {
public:

	bool VERBOSE;
	bool dropOnExit; //for facilitating debugging, if true, it drops the tables created when leaving


	//=== Constructors ==== //

	/*
	 * If no "masterKey" is provided, the current client will not run in the secure mode (queries are plain).
	 */

	EDBClient(const string &masterKey);
	EDBClient();
	EDBClient(string server, string user, string psswd, string dbname, const string &masterKey, uint port = 0);//constructor for security
	EDBClient(string server, string user, string psswd, string dbname); //constructor for no security


	// ========= QUERIES ===== //

	/* Two ways of using CryptDB:
	 *   1. end-to-end query execution
	 *   2. query and response translation
	 */


	//Mode 1: Translation of query, execution of query, and translation of results
	ResType * execute(const char * query);
	//no security:
	ResType * plain_execute(const char * query);


	//Mode 2: Only translations
    //query must be \0 terminated
    list<const char*> rewriteEncryptQuery(const char * query, AutoInc * ai = NULL) throw (SyntaxError);
    //query should be the original, untranslated query
    ResType  * decryptResults(const char * query, ResType * dbAnswer);


    //==== EXIT =================//

	~EDBClient();
	void exit(bool dropOnExit = false); //exists nicely


    //============OPTIMIZATION===================//

    //ENCRYPTION TABLES

    //will create encryption tables and will use them
    //noOPE encryptions and noHOM encryptions
    // only applies to already created tables
    void createEncryptionTables(int noOPE, int noHOM);
    void replenishEncryptionTables();

    // TRAINING

	// trains client on queries from given file and adjusts schema and security level
	int train(string queryFile) throw (SyntaxError);
	// creates tables and indexes at the server based on queries seen
	int train_finish() throw (SyntaxError);
	int create_trained_instance(bool submit = true) throw (SyntaxError);

	//=========== DEBUGGING AND INFO ==============================//

	void outputOnionState();
	//temporarily public for testing
	void getEncForFromFilter(command comm, list<string> query, TMKM & tmkm, QueryMeta & qm);


private:
	bool isSecure;
	bool isTraining;

	Connect * conn; // to connect to the DBMs
	CryptoManager * cm; // for cryptography
	ParserMeta * pm; // for speeding up parsing
	MultiPrinc * mp; // deals with multi-principal tasks

	// the MASTER KEY for single-principal
	AES_KEY * mkey;

	// Schema state
	map<string, string> tableNameMap; //map of anonymized table name to table name
	map<string, TableMetadata *> tableMetaMap; //map of table name to table metadata
	unsigned int totalTables;
	unsigned int totalIndexes;


	//**************** HELPER FUNCTIONS *******************************/

	//CREATE
	//the Encrypt functions rewrite a query by anonymizing, encrypting, and translating it; they also generate decryption queries
	//the Decrypt functions decrypt the result from the server
	list<const char*> rewriteEncryptCreate(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptCreate(const char * query, ResType * dbAnswer);

	//INSERT
	list<const char*> rewriteEncryptInsert(const char * query, AutoInc * ai) throw (SyntaxError);
	ResType * rewriteDecryptInsert(const char * query, ResType * dbAnswer);
	//returns the value to be included in an insert a given value of a field/table
	string processValsToInsert(string field, string table, uint64_t salt, string value, TMKM & tmkm);
	// returns the value we should insert for a field for which the INSERT statement does not specify a value
	string getInitValue(string field, string table, AutoInc * ai = NULL);

	//FILTERS ("WHERE")
	//process where clause
	list<const char *>
	processFilters(list<string>::iterator & wordsIt, list<string> & words, QueryMeta & qm, string resultQuery, FieldsToDecrypt fieldsDec, TMKM & tmkm, list<const char *> subqueries = list<const char*>()) throw (SyntaxError);
	string processOperation(string operation, string op1, string op2, QueryMeta & qm, string  encryptedsubquery, TMKM & tmkm) throw (SyntaxError);

	//UPDATE
	list<const char*> rewriteEncryptUpdate(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptUpdate(const char * query, ResType * dbAnswer);

	//SELECT
	list<const char*> rewriteEncryptSelect(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptSelect(const char * query, ResType * dbAnswer);
	ResType * decryptResultsWrapper(const char * query, DBResult * dbres);
	//prepared decryptions
	list<const char*>  processDecryptions(FieldsToDecrypt fieldsDec, TMKM & tmkm) throw (SyntaxError);
	//isSubquery indicates that the current query is a subquery of a large nested query
	list<const char*> rewriteSelectHelper(list<string> words, bool isSubquery = false, list<const char*> subqueries = list<const char*>()) throw (SyntaxError);

	//DROP
	list<const char*> rewriteEncryptDrop(const char * query) throw (SyntaxError) ;
	ResType * rewriteDecryptDrop(const char * query, ResType * dbAnswer);

	//DELETE
	list<const char*> rewriteEncryptDelete(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptDelete(const char * query, ResType * dbAnswer);

	//BEGIN
	list<const char*> rewriteEncryptBegin(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptBegin(const char * query, ResType * dbAnswer);

	//COMMIT
	list<const char*> rewriteEncryptCommit(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptCommit(const char * query, ResType * dbAnswer);

	//ALTER
	list<const char*> rewriteEncryptAlter(const char * query) throw (SyntaxError);
	ResType * rewriteDecryptAlter(const char * query, ResType * dbAnswer);
	list<const char *> processIndex(list<string> & words, list<string>::iterator & wordsIt) throw (SyntaxError);

	//wrapper for the crypto class - changes master key encryption for multi-keying
	string crypt(string data, fieldType ft, string fullname, string anonfullname,
			SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
			//optional, for MULTIPRINC
			TMKM & tmkm, const vector<string> & res = vector<string>());

	// OTHER


    void dropTables();


protected: //these are protected mostly for testing purposes



};

#endif   /* _EDBCLIENT_H */
