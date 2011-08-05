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
    bool dropOnExit;     //for facilitating debugging, if true, it drops the
                         // tables created when leaving

    //=== Constructors ==== //

    /*
     * If no "masterKey" is provided, the current client will not run in the
     * secure mode (queries are plain).
     */

    EDBClient(string server, string user, string psswd, string dbname,
              uint port = 0, bool multiPrinc = false);
    void setMasterKey(const string &mkey);

    // ========= QUERIES ===== //

    /* Two ways of using CryptDB:
     *   1. end-to-end query execution
     *   2. query and response translation
     */

    //Mode 1: Translation of query, execution of query, and translation of
    // results
    ResType execute(const string &query);

    //no security:
    ResType plain_execute(const string &query);

    //Mode 2: Only translations
    //query must be \0 terminated
    list<string> rewriteEncryptQuery(const string &query,
                                     AutoInc * ai = NULL)
        throw (CryptDBError);

    //query should be the original, untranslated query
    ResType decryptResults(const string &query, const ResType &dbAnswer);

    //==== EXIT =================//

    ~EDBClient();
    void exit();     //exists nicely

    //============OPTIMIZATION===================//

    //ENCRYPTION TABLES

    //will create encryption tables and will use them
    //noOPE encryptions and noHOM encryptions
    // only applies to already created tables
    void createEncryptionTables(int noOPE, int noHOM);
    void replenishEncryptionTables();

    // TRAINING

    // trains client on queries from given file and adjusts schema and
    // security level
    int train(string queryFile)
        throw (CryptDBError);
    // creates tables and indexes at the server based on queries seen
    int train_finish()
        throw (CryptDBError);
    int create_trained_instance(bool submit = true)
        throw (CryptDBError);

    //=========== DEBUGGING AND INFO ==============================//

    void outputOnionState();
    //temporarily public for testing
    void getEncForFromFilter(command comm, list<string> query, TMKM & tmkm,
                             QueryMeta & qm);

 private:
    bool isSecure;
    bool isTraining;

    Connect * conn;     // to connect to the DBMs
    CryptoManager * cm;     // for cryptography
    ParserMeta * pm;     // for speeding up parsing
    MultiPrinc * mp;     // deals with multi-principal tasks

    // Schema state
    map<string, string> tableNameMap;     //map of anonymized table name to
                                          // table name
    map<string, TableMetadata *> tableMetaMap;     //map of table name to
                                                   // table metadata
    unsigned int totalTables;
    unsigned int totalIndexes;

    //**************** HELPER FUNCTIONS *******************************/

    //CREATE
    //the Encrypt functions rewrite a query by anonymizing, encrypting, and
    // translating it; they also generate decryption queries
    //the Decrypt functions decrypt the result from the server
    list<string> rewriteEncryptCreate(const string &query)
        throw (CryptDBError);

    //INSERT
    list<string> rewriteEncryptInsert(const string &query, AutoInc * ai)
        throw (CryptDBError);
    //returns the value to be included in an insert a given value of a
    // field/table
    string processValsToInsert(string field, string table, uint64_t salt,
                               string value, TMKM & tmkm, bool null = false);
    // returns the value we should insert for a field for which the INSERT
    // statement does not specify a value
    pair<string, bool> getInitValue(string field, string table, AutoInc * ai = NULL);

    //FILTERS ("WHERE")
    //process where clause
    list<string>
    processFilters(list<string>::iterator & wordsIt, list<string> & words,
                   QueryMeta & qm, string resultQuery,
                   FieldsToDecrypt fieldsDec, TMKM & tmkm,
                   list<string> subqueries = list<string>())
        throw (CryptDBError);
    string processOperation(string operation, string op1, string op2,
                            QueryMeta & qm, string encryptedsubquery,
                            TMKM & tmkm)
        throw (CryptDBError);

    //UPDATE
    list<string> rewriteEncryptUpdate(const string &query)
        throw (CryptDBError);

    //SELECT
    list<string> rewriteEncryptSelect(const string &query)
        throw (CryptDBError);
    ResType rewriteDecryptSelect(const string &query, const ResType &dbAnswer);
    ResType decryptResultsWrapper(const string &query, DBResult * dbres);
    //prepared decryptions
    list<string>  processDecryptions(FieldsToDecrypt fieldsDec,
                                     TMKM & tmkm)
        throw (CryptDBError);
    //isSubquery indicates that the current query is a subquery of a large
    // nested query
    list<string> rewriteSelectHelper(
        list<string> words, bool isSubquery = false,
        list<string> subqueries = list<string>())
        throw (CryptDBError);

    //DROP
    list<string> rewriteEncryptDrop(const string &query)
        throw (CryptDBError);

    //DELETE
    list<string> rewriteEncryptDelete(const string &query)
        throw (CryptDBError);

    //BEGIN
    list<string> rewriteEncryptBegin(const string &query)
        throw (CryptDBError);

    //COMMIT
    list<string> rewriteEncryptCommit(const string &query)
        throw (CryptDBError);

    //ALTER
    list<string> rewriteEncryptAlter(const string &query)
        throw (CryptDBError);
    list<string> processIndex(list<string> & words,
                              list<string>::iterator & wordsIt)
        throw (CryptDBError);

    //wrapper for the crypto class - changes master key encryption for
    // multi-keying
    string crypt(string data, fieldType ft, string fullname,
                 string anonfullname,
                 SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                 //optional, for MULTIPRINC
                 TMKM & tmkm, bool & isBin,
                 const vector<SqlItem> &res = vector<SqlItem>());

    //performs above crypt and marshalls binaries for MySQL query
    string
    dataForQuery(const string &data, fieldType ft,
                 const string &fullname, const string &anonfullname,
                 SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                 //optional, for MULTIPRINC
                 TMKM &tmkm,
                 const vector<SqlItem> &res = vector<SqlItem>());
    // OTHER

    void dropTables();

 protected:
    //these are protected mostly for testing purposes
};

#endif   /* _EDBCLIENT_H */
