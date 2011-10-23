#pragma once

#include <iostream>
#include <fstream>
#include <algorithm>

#include <edb/Translator.hh>
#include <edb/Connect.hh>
#include <edb/MultiPrinc.hh>

#include <parser/embedmysql.hh>

#define TESTING 1
#define NOTDEMO 0

class EDBProxy {
 public:
    bool VERBOSE;
    bool dropOnExit;     //for facilitating debugging, if true, it drops the
                         // tables created when leaving

    //=== Constructors ==== //

    /*
     * If no "masterKey" is provided, the current client will not run in the
     * secure mode (queries are plain).
     */

    EDBProxy(const std::string& server
             , const std::string& user
             , const std::string& psswd
             , const std::string& dbname
             , uint port = 0
             , bool multiPrinc = false
             , bool allDefaultEncrypted = false
             , const std::string& proxy_directory = ""
             );
    void setMasterKey(const std::string &mkey);

    // ========= QUERIES ===== //

    /* Two ways of using CryptDB:
     *   1. end-to-end query execution
     *   2. query and response translation
     */

    //Mode 1: Translation of query, execution of query, and translation of
    // results
    ResType execute(const std::string &query);

    //no security:
    ResType plain_execute(const std::string &query);

    //Mode 2: Only translations
    //query must be \0 terminated
    std::list<std::string> rewriteEncryptQuery(const std::string &query, bool &considered)
        throw (CryptDBError);

    //query should be the original, untranslated query
    ResType decryptResults(const std::string &query, const ResType &dbAnswer);

    //==== EXIT =================//

    ~EDBProxy();
    void exit();     //exists nicely

    //============OPTIMIZATION===================//

    //ENCRYPTION TABLES
  /*
    //will create encryption tables and will use them
    //noOPE encryptions and noHOM encryptions
    // only applies to already created tables
    void createEncryptionTables(int noOPE, int noHOM);
    void replenishEncryptionTables();
    */
    void generateEncTables(std::list<OPESpec> & opes,
                           unsigned int minHOM, unsigned int maxHOM,
                           unsigned int randomPoolSize,
                           std::string outputfile);
    void loadEncTables(std::string filename);
    // TRAINING

    // trains client on queries from given file and adjusts schema and
    // security level
    void
    runQueries(std::string queryFile, bool execute=false) throw (CryptDBError);
    void
    setStateFromTraining();

    //=========== DEBUGGING AND INFO ==============================//

    void outputOnionState();
    //temporarily public for testing
    void getEncForFromFilter(command comm, std::list<std::string> query, TMKM & tmkm,
                             QueryMeta & qm);

 private:
    bool isSecure;
    bool allDefaultEncrypted;
#if NOTDEMO
    embedmysql meta_db; // to connect to the embedded db, persisting meta info
#endif
    Connect * conn;     // to connect to the DBMs
    CryptoManager * cm;     // for cryptography
    ParserMeta * pm;     // for speeding up parsing
    MultiPrinc * mp;     // deals with multi-principal tasks

    // Schema state
    std::map<std::string, std::string> tableNameMap;     //map of anonymized table name to
                                          // table name
    std::map<std::string, TableMetadata *> tableMetaMap;     //map of table name to
                                                   // table metadata
    unsigned int totalTables;
    unsigned int totalIndexes;


    //**************** HELPER FUNCTIONS *******************************/

    //returns true if this query has to do with cryptdb
    // e.g. SET NAMES 'utf8' is a negative example
    // also ignores queries that apply only to non-sensitive tables
#if TESTING
 public:
#endif
    bool considerQuery(command com, const std::string &query);


    //CREATE
    //the Encrypt functions rewrite a query by anonymizing, encrypting, and
    // translating it; they also generate decryption queries
    //the Decrypt functions decrypt the result from the server
    std::list<std::string> rewriteEncryptCreate(const std::string &query)
        throw (CryptDBError);
    bool overwrite_creates;

    //INSERT
    std::list<std::string> rewriteEncryptInsert(const std::string &query)
        throw (CryptDBError);
    //returns the value to be included in an insert a given value of a
    // field/table
    std::string processValsToInsert(std::string field, FieldMetadata * fm, std::string table, TableMetadata * tm, uint64_t salt,
                               std::string value, TMKM & tmkm, bool null = false);


    //FILTERS ("WHERE")
    //process where clause
    std::list<std::string>
    processFilters(std::list<std::string>::iterator & wordsIt, std::list<std::string> & words,
                   QueryMeta & qm, std::string resultQuery,
                   FieldsToDecrypt fieldsDec, TMKM & tmkm,
                   std::list<std::string> subqueries = std::list<std::string>())
        throw (CryptDBError);
    std::string processOperation(std::string operation, std::string op1, std::string op2,
                            QueryMeta & qm, std::string encryptedsubquery,
                            TMKM & tmkm)
        throw (CryptDBError);

    //UPDATE
    std::list<std::string> rewriteEncryptUpdate(const std::string &query)
        throw (CryptDBError);

    //SELECT
    std::list<std::string> rewriteEncryptSelect(const std::string &query)
        throw (CryptDBError);
    ResType rewriteDecryptSelect(const std::string &query, const ResType &dbAnswer);
    ResType decryptResultsWrapper(const std::string &query, DBResult * dbres);
    //prepared decryptions
    std::list<std::string>  processDecryptions(FieldsToDecrypt fieldsDec,
                                     TMKM & tmkm)
        throw (CryptDBError);
    //isSubquery indicates that the current query is a subquery of a large
    // nested query
    std::list<std::string> rewriteSelectHelper(
        std::list<std::string> words, bool isSubquery = false,
        std::list<std::string> subqueries = std::list<std::string>())
        throw (CryptDBError);

    //DROP
    std::list<std::string> rewriteEncryptDrop(const std::string &query)
        throw (CryptDBError);

    //DELETE
    std::list<std::string> rewriteEncryptDelete(const std::string &query)
        throw (CryptDBError);

    //BEGIN
    std::list<std::string> rewriteEncryptBegin(const std::string &query)
        throw (CryptDBError);

    //COMMIT
    std::list<std::string> rewriteEncryptCommit(const std::string &query)
        throw (CryptDBError);

    //ALTER
    std::list<std::string> rewriteEncryptAlter(const std::string &query)
        throw (CryptDBError);
    std::list<std::string> processIndex(std::list<std::string> & words,
                              std::list<std::string>::iterator & wordsIt)
        throw (CryptDBError);

    //wrapper for the crypto class - changes master key encryption for
    // multi-keying
    std::string crypt(std::string data, fieldType ft, std::string fullname,
                 std::string anonfullname,
                 SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                 //optional, for MULTIPRINC
                 TMKM & tmkm, bool & isBin,
                 const std::vector<SqlItem> &res = std::vector<SqlItem>());

    //performs above crypt and marshalls binaries for MySQL query
    std::string
    dataForQuery(const std::string &data, fieldType ft,
                 const std::string &fullname, const std::string &anonfullname,
                 SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                 //optional, for MULTIPRINC
                 TMKM &tmkm,
                 const std::vector<SqlItem> &res = std::vector<SqlItem>());
    // OTHER

    void dropTables();


    //syntax: train are_all_fields_encrypted createsfile indexfile queryfile
    std::list<std::string> rewriteEncryptTrain(const std::string & query);

#if NOTDEMO
    void readMetaInfo( ); // used by ctor to retrieve meta info from embedded database
#endif

 protected:
    //these are protected mostly for testing purposes
};
