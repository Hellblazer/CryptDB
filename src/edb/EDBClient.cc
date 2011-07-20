#include "EDBClient.h"
#include "log.h"

#include <iostream>
#include <fstream>
#include <set>

#if MYSQL_S

#define DECRYPT_int_sem "decrypt_int_sem"
#define DECRYPT_int_det "decrypt_int_det"
#define ENCRYPT_int_det "encrypt_int_det"
#define DECRYPT_text_sem "decrypt_text_sem"
#define DECRYPT_text_det "decrypt_text_det"
#define SEARCH "search"
#define FUNC_ADD_FINAL "agg"
#define SUM_AGG "agg"
#define FUNC_ADD_SET "func_add_set"
#define SEARCHSWP "searchSWP"

#else

#define DECRYPT_int_sem \
    "decrypt_int_sem( bigint, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, bigint)"
#define DECRYPT_int_det \
    "decrypt_int_det( bigint, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer)"
#define DECRYPT_text_sem \
    "decrypt_text_sem( bytea, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, integer, bigint)"
#define SEARCH "search(bytea, bytea)"
#define FUNC_ADD "func_add(bytea, bytea)"
#define FUNC_ADD_FINAL "func_add_final(bytea)"
#define FUNC_ADD_SET "func_add_set(bytea, bytea, bytea)"
#define AGG "agg"

#endif

static bool VERBOSE_V = VERBOSE_EDBCLIENT_VERY;

static void
dropAll(Connect * conn)
{

    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " DECRYPT_int_sem "; "),
             "cannot drop " DECRYPT_int_sem);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " DECRYPT_int_det "; "),
             "cannot drop " DECRYPT_int_det);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " ENCRYPT_int_det "; "),
             "cannot drop " ENCRYPT_int_det);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " DECRYPT_text_sem "; "),
             "cannot drop " DECRYPT_text_sem);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " DECRYPT_text_det "; "),
             "cannot drop " DECRYPT_text_det);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " SEARCH "; "),
             "cannot drop " SEARCH);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " FUNC_ADD_FINAL "; "),
             "cannot drop " FUNC_ADD_FINAL);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " FUNC_ADD_SET "; "),
             "cannot drop " FUNC_ADD_SET);

    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " SEARCHSWP "; "),
             "cannot drop " SEARCHSWP);

#if MYSQL_S
#else
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " FUNC_ADD "; "),
             "cannot drop " FUNC_ADD);
    myassert(conn->execute(
                 "DROP AGGREGATE IF EXISTS agg_sum(bytea) ; "),
             "cannot drop agg_sum");
#endif

}

static void
createAll(Connect * conn, CryptoManager * cm)
{
    myassert(conn->execute(
                 "CREATE FUNCTION decrypt_int_sem RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf decrypt_int_sem ");
    myassert(conn->execute(
                 "CREATE FUNCTION decrypt_int_det RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf decrypt_int_det");
    myassert(conn->execute(
                 "CREATE FUNCTION encrypt_int_det RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf encrypt_int_det");
    myassert(conn->execute(
                 "CREATE FUNCTION decrypt_text_sem RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf decrypt_text_sem");
    myassert(conn->execute(
                 "CREATE FUNCTION decrypt_text_det RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf decrypt_text_det");
    myassert(conn->execute(
                 "CREATE FUNCTION search RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf search");
    myassert(conn->execute(
                 "CREATE AGGREGATE FUNCTION agg RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf agg");
    myassert(conn->execute(
                 "CREATE FUNCTION func_add_set RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf func_add_set");
    myassert(conn->execute(
                 "CREATE FUNCTION searchSWP RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf searchSWP");

    /* old Postgres statements: */
    /*
       assert(conn->execute(
            "CREATE FUNCTION " DECRYPT_int_sem  " RETURNS bigint  AS " F_PATH
               " LANGUAGE C; \n"
            "CREATE FUNCTION " DECRYPT_int_det  " RETURNS bigint  AS " F_PATH
               " LANGUAGE C; \n"
            "CREATE FUNCTION " DECRYPT_text_sem " RETURNS bytea   AS " F_PATH
               " LANGUAGE C; \n"
            "CREATE FUNCTION " SEARCH           " RETURNS bool    AS " F_PATH
               " LANGUAGE C; \n"
            "CREATE FUNCTION " FUNC_ADD         " RETURNS bytea   AS " F_PATH
               " LANGUAGE C STRICT; \n"
            "CREATE FUNCTION " FUNC_ADD_FINAL   " RETURNS bytea   AS " F_PATH
               " LANGUAGE C STRICT; \n"
            "CREATE FUNCTION " FUNC_ADD_SET     " RETURNS bytea   AS " F_PATH
               " LANGUAGE C STRICT; \n", "cannot create udfs ");

       string createSumAgg = " CREATE AGGREGATE agg_sum ( basetype = bytea,
          sfunc = func_add, finalfunc = func_add_final,  stype = bytea,
          initcond = " + initcond(cm) + ");";

       if (!conn->execute(createSumAgg)) {
            cerr << "cannot create aggregation function \n";
            exit(1);
       }
     */
}

/*
   const char * createInfoTable (CryptoManager * cm) {
        string res = "CREATE TABLE PKINFO (n2 bytea); INSERT INTO PKINFO
           VALUES (";
        res = res + marshallBinary(cm->getPKInfo(), cm->Paillier_len_bytes);
        res = res + ");";
        return res.c_str();
   }
 */

//============== CONSTRUCTORS ==================================//

EDBClient::EDBClient(string server, string user, string psswd, string dbname,
                     const string &masterKey,
                     uint port)
{
    //conninfo = "host=farm10 dbname = " + conninfo;
    this->isSecure = true;
    this->cm = new CryptoManager(masterKey);
    mkey = cm->get_key_DET(masterKey);

    string PK = marshallBinary(cm->getPKInfo());

    VERBOSE = VERBOSE_EDBCLIENT;
    dropOnExit = false;

    /* Make a connection to the database */
    conn = new Connect(server, user, psswd, dbname, port);

    dropAll(conn);
    createAll(conn, cm);
    if (VERBOSE) {cout << "UDF-s loaded successfully. \n\n"; }

    tableNameMap = map<string, string>();
    tableMetaMap = map<string, TableMetadata *>();

    totalTables = 0;
    totalIndexes = 0;

    if (MULTIPRINC) {
        mp = new MultiPrinc(conn);
    } else {
        mp = NULL;
    }

}

EDBClient::EDBClient(const string &masterKey)
{
    this->isSecure = true;
    this->cm = new CryptoManager(masterKey);
    mkey = cm->get_key_DET(masterKey);

    string PK = marshallBinary(cm->getPKInfo());

    VERBOSE = VERBOSE_EDBCLIENT;
    dropOnExit = false;

    /* Make a connection to the database */
    conn = NULL;

    tableNameMap = map<string, string>();
    tableMetaMap = map<string, TableMetadata *>();

    totalTables = 0;
    totalIndexes = 0;

    if (MULTIPRINC) {
        mp = new MultiPrinc(conn);
    } else {
        mp = NULL;
    }

}

EDBClient::EDBClient()
{
    this->isSecure = false;
    mp = NULL;

    VERBOSE = false;
    dropOnExit = false;

    /* Make a connection to the database */
    conn = NULL;

    tableNameMap = map<string, string>();
    tableMetaMap = map<string, TableMetadata *>();

    totalTables = 0;
    totalIndexes = 0;

    //dropAll(conn);
    //createAll(conn, cm);

    //if (VERBOSE) {cout << "UDF-s loaded successfully. \n\n";}

}

ResType *
EDBClient::plain_execute(const string &query)
{
    LOG(edb) << "in plain execute";
    DBResult * reply;
    if (!conn->execute(query, reply)) {
        cerr << "failed to execute " << query << "\n";
        return NULL;
    }

    ResType *r = reply->unpack();
    delete reply;
    return r;
}

EDBClient::EDBClient(string server, string user, string psswd, string dbname)
{

    //conninfo = "host = farm10 dbname = " + conninfo;

    this->isSecure = false;
    mp = NULL;
    totalTables = 0;

    VERBOSE = false;

    conn = new Connect(server, user, psswd, dbname);

    if (MULTIPRINC) {
        mp = new MultiPrinc(conn);
    } else {
        mp = NULL;
    }

}

//ENCRYPTION TABLES

//will create encryption tables and will use them
//noOPE encryptions and noHOM encryptions
void
EDBClient::createEncryptionTables(int noOPE, int noHOM)
{

    list<string> fieldsWithOPE;

    for (map<string, TableMetadata *>::iterator tit = tableMetaMap.begin();
         tit != tableMetaMap.end(); tit++) {
        TableMetadata * tm = tit->second;
        for (map<string, FieldMetadata *>::iterator fit =
                 tm->fieldMetaMap.begin();
             fit != tm->fieldMetaMap.end(); fit++) {
            FieldMetadata * fm = fit->second;
            if (fm->exists(fm->anonFieldNameOPE)) {
                fieldsWithOPE.push_back(fullName(fm->anonFieldNameOPE,
                                                 tm->anonTableName));
            }
        }
    }

    cm->createEncryptionTables(noOPE, noHOM, fieldsWithOPE);

}

void
EDBClient::replenishEncryptionTables()
{
    cm->replenishEncryptionTables();
}

static fieldType
getType(list<string>::iterator & it, list<string> & words)
{

    unsigned int noTerms = 2;
    string terms[] = {",", ")"};
    string token = *it;
    bool isint = false;
    if (it->find("int") != string::npos) {
        isint = true;
    }
    if (it->find("decimal") != string::npos) {
        isint = true;
    }

    it++;

    mirrorUntilTerm(it, words, terms, noTerms, 0, 1);

    if (isint) {
        return TYPE_INTEGER;
    } else {
        return TYPE_TEXT;
    }

}

list<string>
EDBClient::processIndex(list<string> & words,
                        list<string>::iterator & wordsIt)
throw (CryptDBError)
{

    //create index ndx_customer_name
    // on customer (c_w_id, c_d_id, c_last, c_first);

    assert_s(false, "needs revision, including lowercasing");
    string resultQuery = "create ";
    bool isUnique = false;

    if (wordsIt->compare("unique") == 0) {
        resultQuery = resultQuery + "unique ";
        isUnique = true;
        wordsIt++;
    }

    assert_s(wordsIt->compare("index") == 0, "expected keyword index ");
    wordsIt++;
    resultQuery = resultQuery + " index ";

    string indexName = *wordsIt;
    wordsIt++;
    resultQuery = resultQuery + indexName;

    assert_s(wordsIt->compare("on") == 0, "expected keyword 'on' ");
    wordsIt++;
    resultQuery = resultQuery + " on ";

    string table = *wordsIt;
    assert_s(isTable(table, tableMetaMap), " it is not a table: " + table);
    string anonTable = tableMetaMap[table]->anonTableName;
    resultQuery = resultQuery + anonTable;
    wordsIt++;

    assert_s(wordsIt->compare("(") == 0, "expected (");
    resultQuery = resultQuery + " (";
    wordsIt++;

    IndexMetadata * im = new IndexMetadata;
    im->anonIndexName = string("index") + marshallVal(totalIndexes);
    totalIndexes++;
    im->isUnique = isUnique;
    tableMetaMap[table]->indexes.push_back(im);

    while (wordsIt->compare(")") != 0) {
        string fieldName = *wordsIt;
        string anonFieldName = getOnionName(
            tableMetaMap[table]->fieldMetaMap[fieldName], oDET);
        checkStr(++wordsIt,words,",", ")");
        resultQuery = resultQuery  + anonFieldName + " ,";

        im->fields.push_back(fieldName);

    }

    resultQuery[resultQuery.length() - 1] = ' ';

    resultQuery = resultQuery + ")";
    wordsIt++;
    if (wordsIt != words.end()) {cerr << "it is " << *wordsIt << "\n"; }

    assert_s(wordsIt == words.end(), "expected end of query, it continues");

    list<string> result;
    result.push_back(resultQuery);

    return result;
}

/*
   static bool
   isEncrypted(string token)
   {
    if (MULTIPRINC) {
        return (toLowerCase(token).compare("encfor") == 0);
    } else {
        return (toLowerCase(token).compare("enc") == 0);
    }
   }
 */

static string
getNameForFilter(FieldMetadata * fm, onion o)
{
    if (!fm->isEncrypted) {
        return fm->fieldName;
    }
    if (o == oDET) {
        //for equality type operations use OPE if you can
        if (fm->exists(fm->anonFieldNameOPE) &&
            (fm->secLevelOPE != SEMANTIC_OPE)) {
            return fm->anonFieldNameOPE;
        } else {
            return fm->anonFieldNameDET;
        }
    }
    if (o == oOPE) {
        return fm->anonFieldNameOPE;
    }
    if (o == oAGG) {
        return fm->anonFieldNameAGG;
    }
    assert_s(false, "unknown onion ");
    return "";
}

static void
processAnnotation(MultiPrinc * mp, list<string>::iterator & wordsIt,
                  list<string> & words, string tableName, string fieldName,
                  FieldMetadata * fm, map<string, TableMetadata *> & tm)
{
    if (DECRYPTFIRST) {
        tm[tableName]->fieldMetaMap[fieldName]->secLevelDET = DETJOIN;
        //make ope onion uncovered to avoid adjustment --- though this onion
        // does not exist in this mode
        tm[tableName]->fieldMetaMap[fieldName]->secLevelOPE = OPESELF;
        return;
    }

    fm->isEncrypted = false;

    while (annotations.find(*wordsIt) != annotations.end()) {
        string annot = toLowerCase(*wordsIt);

        if (annot == "enc") {
            fm->isEncrypted = true;
            if (!MULTIPRINC) {
                fm->ope_used = true;
                fm->agg_used = true;
            }
            wordsIt++;
            continue;
        }

        if (annot == "search") {
            fm->has_search = true;
            wordsIt++;
            continue;
        }

        // MULTI-PRINC annotations

        if (annot == "encfor") {
            fm->isEncrypted = true;
        }

        mp->processAnnotation(wordsIt, words, tableName, fieldName,
                              fm->isEncrypted,
                              tm);

    }

}

list<string>
EDBClient::rewriteEncryptCreate(const string &query)
throw (CryptDBError)
{
    LOG(edb) << "in create";

    list<string> words = getSQLWords(query);

    list<string>::iterator wordsIt = words.begin();
    wordsIt++;

    LOG(edb) << "done with sql words";

    if (toLowerCase(*wordsIt).compare("table") != 0) {

        //index
        assert_s(equalsIgnoreCase(*wordsIt,
                                  "index") || equalsIgnoreCase(*wordsIt,
                                                               "unique"),
                 "expected index/unique ");

        if (DECRYPTFIRST)
            return list<string>(1, query);

        return processIndex(words, wordsIt);
    }

    wordsIt++;

    //get table name
    string tableName = *wordsIt;

    assert_s(tableMetaMap.find(
                 tableName) == tableMetaMap.end(),"table already exists: " +
             tableName );

    unsigned int tableNo = totalTables;
    totalTables++;
    //create anon name
    string anonTableName = anonymizeTableName(tableNo, tableName);

    tableNameMap[anonTableName] = tableName;

    //create new table structure
    TableMetadata * tm = new TableMetadata;
    tableMetaMap[tableName] = tm;

    //populate table structure
    tm->fieldNames = list<string>();
    tm->tableNo = tableNo;
    tm->anonTableName = anonTableName;
    tm->fieldNameMap = map<string, string>();
    tm->fieldMetaMap = map<string, FieldMetadata *>();
    tm->hasEncrypted = false;
    //fill the fieldNameMap and fieldMetaMap and prepare the anonymized query

    string resultQuery = "CREATE TABLE ";
    resultQuery = resultQuery + anonTableName + " ( ";

    roll<string>(wordsIt, 2);
    unsigned int i = 0;

    unsigned int noTerms = 2;
    string terms[] = {",", ")"};

    string fieldSeq = "";

    while (wordsIt != words.end()) {
        string fieldName = *wordsIt;

        //primary key, index, other metadata about data layout
        if (contains(fieldName, createMetaKeywords, noCreateMeta)) {
            if (VERBOSE) { cerr << fieldName << " is meta \n"; }
            //mirrorUntilTerm should stop at the comma
            fieldSeq +=  mirrorUntilTerm(wordsIt, words, terms, 1, 1, 1);
            continue;
        }

        assert_s(tm->fieldMetaMap.find(
                     fieldName) == tm->fieldMetaMap.end(),
                 "field %s already exists in table " +  fieldName + " " +
                 tableName);

        tm->fieldNames.push_back(fieldName);

        FieldMetadata * fm = new FieldMetadata();

        fm->fieldName = fieldName;
        wordsIt++;

        tm->fieldMetaMap[fieldName] =  fm;

        LOG(edb_v) << "fieldname " << fieldName;

        //decides if this field is encrypted or not
        processAnnotation(mp, wordsIt, words, tableName, fieldName,
                          fm,
                          tableMetaMap);

        if (fm->isEncrypted) {
            LOG(edb_v) << "encrypted field";
            tm->hasEncrypted = true;
        } else {
            LOG(edb_v) << "not enc " << fieldName;
            fieldSeq +=  fieldName + " " +
                        mirrorUntilTerm(wordsIt, words, terms, 1, 1,
                                        1);
            continue;
        }

        fm->type = getType(wordsIt, words);

        fieldSeq += processCreate(fm->type, fieldName, i, tm,
                                  fm) + " ";

        fieldSeq +=  mirrorUntilTerm(wordsIt, words, terms, noTerms);

        i++;
    }

    if (!DECRYPTFIRST) {
        if (tm->hasEncrypted) {
            resultQuery += " salt " TN_I64 ", ";
        }
    }

    resultQuery += fieldSeq;

    //mirror query until the end, it may have formatting commands
    resultQuery = resultQuery + mirrorUntilTerm(wordsIt, words, terms, 0);
    resultQuery = resultQuery + ";" + '\0';

    return list<string>(1, resultQuery);
}

//TODO: MULTIPRINC does not have update fully implemented
list<string>
EDBClient::rewriteEncryptUpdate(const string &query)
throw (CryptDBError)
{

    //	UPDATE folders SET mitgeec = 'DOC', mitgeecs_app_term = '9/2007' WHERE
    // id = '99e89298fa'

    FieldsToDecrypt fieldsDec;

    list<string> words = getSQLWords(query);
    QueryMeta qm = getQueryMeta(UPDATE, words, tableMetaMap);

    TMKM tmkm;
    if (MULTIPRINC) {
        tmkm.processingQuery = true;
        mp->getEncForFromFilter(UPDATE, words, tmkm, qm, tableMetaMap);
    }

    list<string>::iterator wordsIt = words.begin();

    //skip over UPDATE
    string resultQuery = "UPDATE ";
    wordsIt++;

    //table
    assert_s(tableMetaMap.find(
                 *wordsIt) != tableMetaMap.end(),
             " table to update does not exist" );

    resultQuery = resultQuery + tableMetaMap[*wordsIt]->anonTableName;
    wordsIt++;

    //skip over SET
    resultQuery = resultQuery + " SET ";
    wordsIt++;

    while ((wordsIt != words.end()) &&
           (!equalsIgnoreCase(*wordsIt,"where"))) {
        string table, field;
        string currentField = *wordsIt;
        getTableField(*wordsIt, table, field, qm, tableMetaMap);

        wordsIt++;

        string term[] = {",", "where"};
        unsigned int noTerms = 2;

        FieldMetadata * fm1 = tableMetaMap[table]->fieldMetaMap[field];

        if (!fm1->isEncrypted) {
            resultQuery = resultQuery + " " + field +  mirrorUntilTerm(
                wordsIt, words, term, noTerms, 0, 1);
            if (wordsIt == words.end()) {
                continue;
            }
            if (wordsIt->compare(",") == 0) {
                resultQuery += ", ";
                wordsIt++;
            }
            continue;
        }

        string anonTableName = tableMetaMap[table]->anonTableName;
        wordsIt++;
        fieldType ft = fm1->type;

        //detect if it is an increment
        if (isField(*wordsIt)) {         //this is an increment

            if (VERBOSE) { cerr << "increment for " << field << "\n"; }

            fm1->INCREMENT_HAPPENED = true;
            string anonFieldName = getOnionName(
                tableMetaMap[table]->fieldMetaMap[field], oAGG);

            // get information about the field on the right of =
            string table2, field2;
            getTableField(*wordsIt, table2, field2, qm, tableMetaMap);
            FieldMetadata * fm2 = tableMetaMap[table2]->fieldMetaMap[field2];
            string anonName2 = fieldNameForQuery(
                tableMetaMap[table2]->anonTableName, table2,
                getOnionName(fm2, oAGG),fm2->type, qm);

            wordsIt++;
            bool isEncrypted1 = fm1->isEncrypted;
            assert_s(
                isEncrypted1 == fm2->isEncrypted,
                "must both be encrypted or not\n");
            assert_s((!isEncrypted1) || wordsIt->compare(
                         "+") == 0, "can only update with plus");
            string op = *wordsIt;
            wordsIt++;             // points to value now

            fm1->agg_used = true;
            fm2->agg_used = true;

            if (isEncrypted1) {
                fm1->agg_used = false;
                fm2->agg_used = false;
                if (DECRYPTFIRST) {
                    resultQuery += field + " =  encrypt_int_det( "+
                                   fieldNameForQuery(
                        tableMetaMap[table]->anonTableName,
                        table, field2,
                        TYPE_INTEGER,
                        qm) +  " + " +
                                   *wordsIt + ", "+
                                   CryptoManager::marshallKey(
                        dec_first_key) + ") ";
                } else {
                    resultQuery += anonFieldName + " =  func_add_set (" +
                                   anonName2 +  ", "
                                   + crypt(*wordsIt, ft,
                                           fullName(field,
                                                    table),
                                           fullName(anonFieldName,
                                                    tableMetaMap[table]->
                                                    anonTableName),
                                           PLAIN_AGG, SEMANTIC_AGG, 0,
                                           tmkm) + ", "
                                   + marshallBinary(cm->getPKInfo()) + ") ";
                }
            } else {
                resultQuery = resultQuery + anonFieldName + " = " +
                              anonName2 + op + " " + *wordsIt;
            }

            wordsIt++;

            resultQuery += checkStr(wordsIt, words, ",", "");
            continue;
        }

        //encryption fields that are not increments

        if (ft == TYPE_INTEGER) {
            string val = *wordsIt;

            //pass over value
            wordsIt++;

            SECLEVEL sldet = fm1->secLevelDET;
            string anonfieldName = getOnionName(fm1, oDET);

            resultQuery = resultQuery + anonfieldName  + " = ";

            if (DECRYPTFIRST) {
                resultQuery += processValsToInsert(field, table, 0, val, tmkm);
            } else {
                if (sldet == SEMANTIC_DET) {
                    //we need to lower the security level of the column
                    addIfNotContained(fullName(field,
                                               table), fieldsDec.DETFields);
                    resultQuery +=
                        crypt(val, TYPE_INTEGER,
                              fullName(field,
                                       table), fullName(anonfieldName,
                                                        anonTableName),
                              PLAIN_DET, DET, 0, tmkm);

                } else {
                    resultQuery = resultQuery +
                                  crypt(val, TYPE_INTEGER,
                                        fullName(field,
                                                 table),
                                        fullName(anonfieldName,
                                                 anonTableName),
                                        PLAIN_DET, sldet, 0, tmkm);
                }

                if (FieldMetadata::exists(fm1->anonFieldNameOPE)) {

                    SECLEVEL slope = fm1->secLevelOPE;
                    anonfieldName = fm1->anonFieldNameOPE;
                    resultQuery = resultQuery  + ", " + anonfieldName + " = ";
                    if (slope == SEMANTIC_OPE) {
                        addIfNotContained(fullName(field,
                                                   table),
                                          fieldsDec.OPEFields);
                    }
                    resultQuery = resultQuery +
                                  crypt(val, TYPE_INTEGER,
                                        fullName(field,
                                                 table),
                                        fullName(anonfieldName,
                                                 anonTableName),
                                        PLAIN_OPE, OPESELF, 0, tmkm);

                }
                if (FieldMetadata::exists(fm1->anonFieldNameAGG)) {
                    anonfieldName = fm1->anonFieldNameAGG;
                    resultQuery = resultQuery  + ", " + anonfieldName +
                                  " = " +
                                  crypt(val, TYPE_INTEGER,
                                        fullName(field,
                                                 table),
                                        fullName(anonfieldName,
                                                 anonTableName),
                                        PLAIN_AGG, SEMANTIC_AGG, 0, tmkm);
                }
            }
        }
        if (ft == TYPE_TEXT) {

            assert_s(hasApostrophe(
                         *wordsIt), "missing apostrophe for type text");

            if (DECRYPTFIRST) {
                resultQuery = resultQuery + " "  + field + " = " +
                              processValsToInsert(field, table, 0, *wordsIt,
                                                  tmkm);
            } else {

                if (fm1->isEncrypted) {
                    //DET onion
                    if (fm1->secLevelDET == SEMANTIC_DET) {
                        addIfNotContained(fullName(field,
                                                   table),
                                          fieldsDec.DETFields);
                        fm1->secLevelDET = DET;
                    }

                    //encrypt the value
                    string anonfieldname = getOnionName(fm1, oDET);

                    resultQuery = resultQuery + " "  + anonfieldname +
                                  " = " +
                                  crypt(*wordsIt, TYPE_TEXT,
                                        fullName(field,
                                                 table),
                                        fullName(anonfieldname,
                                                 anonTableName),
                                        PLAIN_DET, fm1->secLevelDET, 0, tmkm);

                    //OPE onion
                    if (fm1->exists(fm1->anonFieldNameOPE)) {
                        string anonName = fm1->anonFieldNameOPE;

                        if (fm1->secLevelDET == SEMANTIC_OPE) {
                            addIfNotContained(fullName(field,
                                                       table),
                                              fieldsDec.OPEFields);
                            fm1->secLevelDET = OPESELF;
                        }

                        resultQuery += ", " + anonName + " = " +
                                       crypt(*wordsIt, TYPE_TEXT,
                                             fullName(field,table),
                                             fullName(anonName,
                                                      anonTableName),
                                             PLAIN_OPE, fm1->secLevelOPE, 0,
                                             tmkm);
                    }

                    //OPE onion
                    if (fm1->exists(fm1->anonFieldNameSWP)) {
                        string anonName = fm1->anonFieldNameSWP;

                        resultQuery += ", " + anonName + " = " +
                                       crypt(*wordsIt, TYPE_TEXT,
                                             fullName(field,table),
                                             fullName(anonName, anonTableName),
                                             PLAIN_SWP, SWP, 0, tmkm);
                    }

                } else {
                    resultQuery = resultQuery + " " + field + " = " +
                                  *wordsIt;
                }

            }
            wordsIt++;

        }

        resultQuery += checkStr(wordsIt, words, ",", "");
    }

    list<string>  res =
        processFilters(wordsIt, words, qm,  resultQuery, fieldsDec,
                       tmkm);

    tmkm.cleanup();
    qm.cleanup();

    return res;
}

list<string>
EDBClient::processFilters(list<string>::iterator &  wordsIt,
                          list<string> & words, QueryMeta & qm,
                          string resultQuery,
                          FieldsToDecrypt fieldsDec, TMKM & tmkm,
                          list<string> subqueries)
throw (CryptDBError)
{
    string keys[] = {"AND", "OR", "NOT", "(", ")"};
    unsigned int noKeys = 5;

    if (wordsIt == words.end()) {     //no WHERE clause
        resultQuery = resultQuery + ";";
        goto decryptions;
    }

    //currently left join is not supported
    while (equalsIgnoreCase(*wordsIt,"left")) {
        resultQuery = resultQuery + "left join ";
        wordsIt++;
        assert_s(equalsIgnoreCase(*wordsIt,
                                  "join"),
                 "expected left join, got left only");
        wordsIt++;
        //this goes up to on
        resultQuery +=
            mirrorUntilTerm(wordsIt, words, parserMeta.querySeparators_p, 1,
                            1);
        //goes up to next separator
        resultQuery +=
            mirrorUntilTerm(wordsIt, words, parserMeta.querySeparators_p, 0,
                            1);
        if (wordsIt == words.end()) {
            resultQuery += ";";
            goto decryptions;
        }
    }

    if (!equalsIgnoreCase(*wordsIt,"where")) {
        //cerr << *wordsIt << " is not where \n";
        goto groupings;
    }

    //there is a WHERE clause
    wordsIt++;     //pass over "WHERE"

    resultQuery = resultQuery + " WHERE ";

    //translate fields again
    while ((wordsIt != words.end()) && (!isQuerySeparator(*wordsIt))) {

        //cerr << "in loop " << *wordsIt << "\n";
        //case: keyword
        if (contains(*wordsIt, keys, noKeys)) {
            resultQuery += " " + *wordsIt;
            wordsIt++;
            continue;
        }

        //case: operation does not have sensitive fields
        string res;

        bool iss = processSensitive(wordsIt, words, res, qm, tableMetaMap);

        if (!iss) {
            //the current operation does not have sensitive fields
            LOG(edb) << "no sensitive fields";
            resultQuery = resultQuery + " " + res;
            continue;
        }

        //case: sensitive
        string operand1 = *wordsIt;        //first token of an expression
        wordsIt++;
        string op = *wordsIt;
        wordsIt++;
        string operand2 = *wordsIt;

        //need to figure out what decryption queries to issue
        processDecryptionsForOp(op, operand1, operand2, fieldsDec, qm,
                                tableMetaMap);
        string subquery = "*";

        if (subqueries.size() > 0) {
            subquery = "( " + string(subqueries.front()) + " )";
            subqueries.pop_front();
        }

        LOG(edb) << "before processop for " << operand1 << " " << operand2;
        resultQuery = resultQuery +
                      processOperation(op, operand1, operand2,  qm, subquery,
                                       tmkm);
        wordsIt++;
    }

    if (wordsIt != words.end())
        LOG(edb_v) << "next is " << *wordsIt;

groupings:
    /****
     * ORDER BY, GROUP BY, LIMIt
     */

    while ((wordsIt != words.end()) &&
           (equalsIgnoreCase(*wordsIt,
                             "order") ||
            equalsIgnoreCase(*wordsIt,"group"))) {
        string comm = *wordsIt;
        resultQuery += " " + *wordsIt; wordsIt++;
        assert_s(equalsIgnoreCase(*wordsIt,
                                  "by"), "BY should come after " + comm);
        resultQuery += " " + *wordsIt; wordsIt++;

        while ((wordsIt != words.end()) && isField(*wordsIt)) {
            string token = *wordsIt;
            string table, field;

            getTableField(token, table, field, qm, tableMetaMap);

            FieldMetadata * fm;
            string anonField;

            if (table.length() == 0) {
                //is alias
                resultQuery += " " + token;
                goto ascdesc;
            }

            //not alias

            fm = tableMetaMap[table]->fieldMetaMap[field];

            comm = toLowerCase(comm);

            if (comm.compare("order") == 0) {
                fm->ope_used = true;

                if (fm->secLevelOPE == SEMANTIC_OPE) {
                    addIfNotContained(fullName(field,
                                               table), fieldsDec.OPEFields);
                }

            } else {                    //group
                if (fm->secLevelDET == SEMANTIC_DET) {
                    addIfNotContained(fullName(field,
                                               table), fieldsDec.DETFields);
                }
            }

            if (comm.compare("group") == 0) {
                anonField = getNameForFilter(fm, oDET);
            } else {
                //order by
                anonField = getNameForFilter(fm, oOPE);

            }

            resultQuery = resultQuery + " " +
                          fieldNameForQuery(
                tableMetaMap[table]->anonTableName, table,
                anonField, fm->type,
                qm);

ascdesc:

            wordsIt++;

            if ((wordsIt != words.end()) &&
                (equalsIgnoreCase(*wordsIt,
                                  "asc") ||
                 equalsIgnoreCase(*wordsIt,"desc"))) {
                resultQuery = resultQuery + " " + *wordsIt + " ";
                wordsIt++;
            }

            resultQuery += checkStr(wordsIt, words, ",", "");

        }

    }

    if ((wordsIt != words.end() && (equalsIgnoreCase(*wordsIt, "limit")))) {
        resultQuery = resultQuery + " limit ";
        wordsIt++;
        resultQuery = resultQuery + *wordsIt + " ";
        wordsIt++;
    }

    resultQuery = resultQuery + ";";
    resultQuery = resultQuery + '\0';

    if (wordsIt != words.end()) {cerr << "we have " << *wordsIt << "\n"; }
    assert_s(
        wordsIt == words.end(),
        "expected end of query at token, but query is not done ");

decryptions:

    //prepares any decryption queries
    list<string> decs = processDecryptions(fieldsDec, tmkm);

    decs.push_back(resultQuery);

    return decs;

}

list<string>
EDBClient::processDecryptions(FieldsToDecrypt fieldsDec, TMKM & tmkm)
throw (CryptDBError)
{
    list<string> result;

    QueryMeta qm;

    for (list<string>::iterator it = fieldsDec.DETFields.begin();
         it != fieldsDec.DETFields.end(); it++) {
        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        if (!tableMetaMap[table]->fieldMetaMap[field]->isEncrypted) {
            continue;
        }

        if (MULTIPRINC) {
            assert_s(false,
                     "there should be no adjustment in multi-key mode\n");
        }

        string whereClause = ";" + '\0';
        string fname = fullName(field, table);

        /*if (MULTIPRINC) {
                assert_s((mkm.encForMap.find(fname) != mkm.encForMap.end()) &&
                   (tmkm.encForVal.find(fname) != tmkm.encForVal.end()),
                   "internal: process decryptions missing data for encrypted
                   field");
                whereClause = " WHERE " + getField(mkm.encForMap[fname]) + " =
                   " + tmkm.encForVal[mkm.encForMap[fname]] + whereClause;
           }*/

        string anonTableName = tableMetaMap[table]->anonTableName;
        string anonfieldName = getOnionName(
            tableMetaMap[table]->fieldMetaMap[field], oDET);

        fieldType ft = tableMetaMap[table]->fieldMetaMap[field]->type;

        string decryptS;
        //first prepare the decryption call string
        switch (ft) {
        case TYPE_INTEGER: {
            decryptS = "decrypt_int_sem(" + anonfieldName + "," +
                       cm->marshallKey(cm->getKey(fullName(anonfieldName,
                                                           anonTableName),
                                                  SEMANTIC_DET)) + ", " +
                       "salt)" + whereClause;
            //cout << "KEY USED TO DECRYPT field from SEM " << anonfieldName
            // << " " << cm->marshallKey(cm->getKey(anonTableName
            // +"."+anonfieldName, SEMANTIC)) << "\n"; fflush(stdout);
            break;
        }
        case TYPE_TEXT: {
            decryptS = "decrypt_text_sem(" + anonfieldName + "," +
                       cm->marshallKey(cm->getKey(fullName(anonfieldName,
                                                           anonTableName),
                                                  SEMANTIC_DET)) + ", " +
                       "salt)" + whereClause;
            break;
        }

        default: {assert_s(false, "invalid type"); }

        }

        string resultQ = string("UPDATE ") +
                         tableMetaMap[table]->anonTableName +
                         " SET " + anonfieldName + "= " + decryptS;

        result.push_back(resultQ);

        tableMetaMap[table]->fieldMetaMap[field]->secLevelDET = DET;
    }

    for (list<string>::iterator it = fieldsDec.OPEFields.begin();
         it != fieldsDec.OPEFields.end(); it++) {
        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        TableMetadata * tm = tableMetaMap[table];

        if (!tm->fieldMetaMap[field]->isEncrypted) {
            continue;
        }

        if (MULTIPRINC) {
            assert_s(false,
                     "there should be no adjustment in multi-key mode\n");
        }
        string whereClause = ";" + '\0';
        string fname = fullName(field, table);

        /*if (MULTIPRINC) {
                assert_s((mkm.encForMap.find(fname) != mkm.encForMap.end()) &&
                   (tmkm.encForVal.find(fname) != tmkm.encForVal.end()),
                   "internal: process decryptions missing data for encrypted
                   field");
                whereClause = " WHERE " + getField(mkm.encForMap[fname]) + " =
                   " + tmkm.encForVal[mkm.encForMap[fname]] + whereClause;
           }*/

        string anonTableName = tm->anonTableName;
        string anonfieldName = tm->fieldMetaMap[field]->anonFieldNameOPE;
        //first prepare the decryption call string
        string decryptS = "decrypt_int_sem("  + anonfieldName + "," +
                          cm->marshallKey(cm->getKey(fullName(anonfieldName,
                                                              anonTableName),
                                                     SEMANTIC_OPE)) +
                          ", " +  "salt)" + whereClause;

        string resultQ = string("UPDATE ") + tm->anonTableName +
                         " SET " + anonfieldName + "= " + decryptS;
        result.push_back(resultQ);

        tm->fieldMetaMap[field]->secLevelOPE = OPESELF;

        tm->fieldMetaMap[field]->ope_used = true;

    }

    // decrypt any fields for join

    for (list<string>::iterator it = fieldsDec.DETJoinFields.begin();
         it != fieldsDec.DETJoinFields.end(); it++) {

        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        if (!tableMetaMap[table]->fieldMetaMap[field]->isEncrypted) {
            continue;
        }
        if (MULTIPRINC) {
            assert_s(false, "join not supported for multi-user ");
        }

        string anonTableName = tableMetaMap[table]->anonTableName;
        string anonfieldName = getOnionName(
            tableMetaMap[table]->fieldMetaMap[field], oDET);

        fieldType ft = tableMetaMap[table]->fieldMetaMap[field]->type;

        string decryptS;
        //first prepare the decryption call string

        switch (ft) {
        case TYPE_INTEGER: {

            decryptS = "decrypt_int_det";

            break;
        }
        case TYPE_TEXT: {
            decryptS = "decrypt_text_det";

            break;
        }

        default: {assert_s(false, "invalid type"); }

        }

        decryptS = decryptS + "(" + anonfieldName + "," +
                   cm->marshallKey(cm->getKey(fullName(anonfieldName,
                                                       anonTableName),
                                              DET)) + ");"+'\0';

        string resultQ = string("UPDATE ") +
                         tableMetaMap[table]->anonTableName +
                         " SET " + anonfieldName + "= " + decryptS;

        //cout << "adding JOIN DEC " << resultQ << "\n"; fflush(stdout);
        result.push_back(resultQ);

        tableMetaMap[table]->fieldMetaMap[field]->secLevelDET = DETJOIN;
    }

    for (list<string>::iterator it = fieldsDec.OPEJoinFields.begin();
         it != fieldsDec.OPEJoinFields.end(); it++) {
        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        //for now, do nothing
        //result.push_back(getCStr(string("UPDATE ") +
        // tableMetaMap[table]->anonTableName +
        //" SET " + tableMetaMap[table]->fieldMetaMap[field]->anonFieldNameDET
        //+ " = DECRYPT(0);"+'\0')); //TODO: link in the right key here

        tableMetaMap[table]->fieldMetaMap[field]->secLevelOPE = OPEJOIN;

        if (MULTIPRINC) {
            assert_s(false,
                     " opejoin adjustment not supported with multi-user\n");
        }
    }

    return result;
}

//returns a list of simple queries from nested queries,

static list<list<string> >
getSimpleQ(const string &query)
{

    list<string> words = getSQLWords(query);

    list<string>::iterator wordsIt = words.begin();

    int open = 0;

    list<list<string> > results;
    list<string> currquery;
    list<string> newquery;

    bool insideIN = false;

    for (; wordsIt != words.end(); wordsIt++) {
        if (Operation::isIN(*wordsIt)) {
            insideIN = true;
            currquery = list<string>();
            open += 1;
            wordsIt++;
            assert_s(wordsIt->compare("(") == 0, "expected ( after IN ");

            newquery.push_back("IN"); newquery.push_back("*");

        } else {

            if (!insideIN) {
                newquery.push_back(*wordsIt);
            } else {
                currquery.push_back(*wordsIt);
            }

            if (wordsIt->compare("(") == 0) {
                open += 1;
            }

            if (wordsIt->compare(")") == 0) {
                assert_s(open>0, "encountered ) not matching ");
                if (insideIN && (open == 1)) {
                    currquery.pop_back();
                    results.push_back(currquery);
                    insideIN = false;
                }
                open--;

            }

        }
    }
    results.push_back(newquery);

    return results;
}

list<string>
EDBClient::rewriteEncryptSelect(const string &query)
throw (CryptDBError)
{

    FieldsToDecrypt fieldsDec;

    if (!isNested(query)) {
        list<string> words = getSQLWords(query);
        LOG(edb) << "after sql words " << toString(words);
        return rewriteSelectHelper(words);
    }

    assert_s(false, "nested currently not supported\n");
    //1. SPLIT NESTED QUERY IN simple queries

    list<list<string> > simpleQ = getSimpleQ(query);

    //2. COLLECT ALL DECRYPTION QUERIES NEEDED

    list<string> decqueries;

    //assemble decryption queries
    for (list<list<string> >::iterator qit = simpleQ.begin();
         qit != simpleQ.end(); qit++) {
        //cerr << "rewrite encrypt select Helper "; myPrint(*qit); cerr <<
        // "\n";
        list<string> auxqueries;
        if (isLastIterator<list<string> >(qit, simpleQ.end())) {
            auxqueries = rewriteSelectHelper(*qit, false);
        } else {
            auxqueries = rewriteSelectHelper(*qit, true);
        }
        //cerr << "helper result "; myPrint(auxqueries); cerr << "\n";
        auxqueries.pop_back();
        decqueries.merge(auxqueries);
    }

    list<string> encqueries;

    //3. NOW THAT ENC LEVELS CONVERGED, REENCRYPT ALL QUERIES

    for (list<list<string> >::iterator qit = simpleQ.begin();
         qit != simpleQ.end(); qit++) {
        if (isLastIterator<list<string> >(qit, simpleQ.end())) {
            break;
        }
        //cerr << "rewrite encrypt select Helper "; myPrint(*qit); cerr <<
        // "\n";
        list<string> auxqueries = rewriteSelectHelper(*qit, true);
        //cerr << "helper result "; myPrint(auxqueries); cerr << "\n";
        assert_s(
            auxqueries.size() == 1,
            " aux queries should be one in size after first pass ");

        string q = auxqueries.back();
        for (;; ) {
            size_t pos = q.find(';');
            if (pos == string::npos)
                break;
            q.erase(pos);
        }
        encqueries.push_back(q);
    }

    //4. RECREATE THE NEWLY NESTED QUERY

    //cerr << "rewrite encrypt select Helper "; myPrint(simpleQ.back()); cerr
    // << "\n";

    list<string> results = rewriteSelectHelper(
        simpleQ.back(), false, encqueries);
    //cerr << "helper result "; myPrint(results); cerr << "\n";
    assert_s(
        results.size() == 1,
        "there should not be any new decryption queries\n");

    decqueries.push_back(results.back());

    return decqueries;

}

static bool
hasWildcard(string expr)
{
    if (expr.compare("*")==0) {
        return true;
    }
    uint64_t len = expr.length();
    if (len <= 1) {
        return false;
    }

    unsigned int len2 = (unsigned int)len;
    if ((expr[len2-2] == '.') && (expr[len2-1]=='*')) {
        return true;
    }
    return false;
}

//expands any * into all the (unanonymized) names of the fields in that table
static void
expandWildCard(list<string> & words, QueryMeta & qm, map<string,
                                                         TableMetadata *> &
               tableMetaMap)
{
    list<string>::iterator wordsIt;

    getFieldsItSelect(words, wordsIt);

    while (!equalsIgnoreCase(*wordsIt, "from")) {

        //we do not want to expand * in aggregate:
        if (isAgg(*wordsIt)) {
            string fieldx, tablex;
            onion ox;
            processAgg(wordsIt, words, fieldx, tablex, ox, qm, tableMetaMap,
                       0);
            continue;
        }
        //case 1: *
        if (wordsIt->compare("*") == 0) {
            int noinserts = 0;
            for (list<string>::iterator tit = qm.tables.begin();
                 tit != qm.tables.end(); tit++) {
                //add comma first if some field names have been inserted
                // already
                if (noinserts > 0) {
                    words.insert(wordsIt, ",");
                }
                TableMetadata * tm = tableMetaMap[*tit];
                list<string> fnames = tm->fieldNames;
                size_t count = fnames.size();
                size_t index = 0;
                for (list<string>::iterator fieldsIt = fnames.begin();
                     fieldsIt != fnames.end(); fieldsIt++ ) {
                    FieldMetadata * fm = tm->fieldMetaMap[*fieldsIt];
                    words.insert(wordsIt,
                                 fieldNameForQuery(*tit, *tit, *fieldsIt,
                                                   fm->type, qm, 1));

                    index++;
                    if (index < count) {                     //add comma only
                                                             // if there are
                                                             // more fields to
                                                             // come
                        words.insert(wordsIt, ",");
                    }
                    noinserts++;

                }
            }
            list<string>::iterator newIt = wordsIt;
            newIt--;
            words.erase(wordsIt);             //erase wildcard
            wordsIt = ++newIt;
            checkStr(wordsIt, words, ",", "from");
            continue;
        }

        //case 2: smth.*
        if (hasWildcard(*wordsIt)) {
            string tn = getBeforeChar(*wordsIt, '.');
            string table;
            if (qm.aliasToTab.find(tn) != qm.aliasToTab.end()) {
                table = qm.aliasToTab[tn];
            } else {
                table = tn;
            }
            TableMetadata * tm = tableMetaMap[table];
            list<string> fnames = tm->fieldNames;
            size_t count = fnames.size();
            size_t index = 0;
            for (list<string>::iterator fieldsIt = fnames.begin();
                 fieldsIt != fnames.end(); fieldsIt++ ) {

                FieldMetadata * fm = tm->fieldMetaMap[*fieldsIt];
                words.insert(wordsIt,
                             fieldNameForQuery(table, table, *fieldsIt,
                                               fm->type, qm, 1));
                index++;
                if (index < count) {                 //add comma only if there
                                                     // are more fields to
                                                     // come
                    words.insert(wordsIt, ",");
                }
            }

            list<string>::iterator newIt = wordsIt;
            newIt--;
            words.erase(wordsIt);             //erase wildcard
            wordsIt = ++newIt;
            checkStr(wordsIt, words, ",", "from");
            continue;
        }
        //case 3: no wildcard
        wordsIt++;

    }

}

list<string>
EDBClient::rewriteSelectHelper(list<string> words, bool isSubquery,
                               list<string> subqueries)
throw (CryptDBError)
{

    /***********************
     * QUERY looks like: SELECT select_body FROM from_body WHERE where_body;
     *
     * -- resultQuery will hold the translated query
     * -- result holds all the decryption queries needed and resultQuery
     **********************/

    //cerr << "words are: "; myPrint(words); cerr << "\n";
    //====PARSING ====
    TMKM tmkm;

    //struct timeval starttime, endtime;

    //first figure out what tables are involved to know what fields refer to
    //gettimeofday(&starttime, NULL);
    QueryMeta qm  = getQueryMeta(SELECT, words, tableMetaMap);
    LOG(edb_v) << "after get query meta";
//	gettimeofday(&endtime, NULL);
//	cout << "get query meta" << timeInMSec(starttime, endtime) << "\n";
    //expand * in SELECT *

//	gettimeofday(&starttime, NULL);
    expandWildCard(words, qm, tableMetaMap);
//	gettimeofday(&endtime, NULL);
//	cout << "expand wild card " << timeInMSec(starttime, endtime) << "\n";
    //=========================================================

    LOG(edb_v) << "new query is " << toString(words);

    list<string>::iterator wordsIt = words.begin();

    //gettimeofday(&starttime, NULL);

    if (MULTIPRINC) {
        tmkm.processingQuery = true;
        mp->prepareSelect(words, tmkm, qm, tableMetaMap);
        if (VERBOSE) { cerr << "done with prepare select \n"; }
    }

//	gettimeofday(&endtime, NULL);
//		cout << "MULTIPRINC prepare select" << timeInMSec(starttime,
// endtime) << "\n";

    FieldsToDecrypt fieldsDec;

    /****************
    *  select_body
    ****************/

    string resultQuery = "SELECT  ";
    roll<string>(wordsIt, 1);

    bool detToAll = false;

    if (equalsIgnoreCase(*wordsIt, "distinct")) {
        resultQuery += " DISTINCT ";
        detToAll = true;
        wordsIt++;
    }

    string oldTable = "";

    while (!equalsIgnoreCase(*wordsIt, "from")) {
        LOG(edb_v) << "query so far: " << resultQuery;

        string table, field;

        if (toLowerCase(*wordsIt).compare("sum") == 0) {
            wordsIt++;
            assert_s(wordsIt->compare(
                         "(") == 0, "sum should be followed by parenthesis");
            wordsIt++;
            string fieldToAgg = *wordsIt;
            wordsIt++;
            //there may be other stuff before first parent
            string termin[] = {")"};
            int noTermin = 1;

            string res = mirrorUntilTerm(wordsIt, words, termin, noTermin, 0,
                                         0);

            assert_s(wordsIt->compare(
                         ")") == 0, ") needed to close sum expression\n  ");
            wordsIt++;

            getTableField(fieldToAgg, table, field, qm, tableMetaMap);

            TableMetadata * tm = tableMetaMap[table];
            FieldMetadata * fm = tm->fieldMetaMap[field];
            fm->agg_used = true;

            string funcname;

            if (fm->isEncrypted) {

                if (DECRYPTFIRST) {
                    resultQuery += " sum(" + fieldNameForQuery(
                        tm->anonTableName, table, field, fm->type, qm) +") ";
                } else {
                    funcname = SUM_AGG;
                    resultQuery += " " + funcname + "( "  + fieldNameForQuery(
                        tm->anonTableName, table, getOnionName(fm,
                                                               oAGG),
                        fm->type, qm) + ", " +
                                   marshallBinary(cm->getPKInfo()) + ") ";
                }

                if (MULTIPRINC) {
                    resultQuery +=
                        mp->selectEncFor(table, field, qm, tmkm, tm,
                                         fm);
                }

            } else {

                funcname = "sum";
                resultQuery = resultQuery + " " + funcname + "( "  + field +
                              res + " ) ";
            }

            resultQuery = resultQuery + processAlias(wordsIt, words);
            continue;

        }

        if (equalsIgnoreCase(*wordsIt,"count")) {

            resultQuery += *wordsIt;
            wordsIt++;
            assert_s(wordsIt->compare(
                         "(") == 0, "missing ( in count expression \n");
            resultQuery += *wordsIt;
            wordsIt++;

            if (toLowerCase(*wordsIt).compare("distinct") == 0) {
                resultQuery += *wordsIt;
                wordsIt++;
                if (wordsIt->compare("(") == 0) {
                    resultQuery += *wordsIt;
                    wordsIt++;
                }
                string tableD, fieldD;
                getTableField(*wordsIt, tableD, fieldD, qm, tableMetaMap);
                FieldMetadata * fmd =
                    tableMetaMap[tableD]->fieldMetaMap[fieldD];
                if (fmd->secLevelDET == SEMANTIC_DET) {
                    addIfNotContained(fullName(fieldD,
                                               tableD), fieldsDec.DETFields);
                }
                if (DECRYPTFIRST) {
                    resultQuery  += " " +
                                    fieldNameForQuery(
                        tableMetaMap[tableD]->anonTableName,
                        tableD, fieldD,
                        fmd->type,
                        qm);

                } else {
                    resultQuery  += " " +
                                    fieldNameForQuery(
                        tableMetaMap[tableD]->anonTableName,
                        tableD,
                        getNameForFilter(fmd,
                                         oDET),
                        fmd->type, qm);
                }
                wordsIt++;
                resultQuery += *wordsIt;
                myassert(wordsIt->compare(
                             ")") ==0,
                         "expected ) after field for DISTINCT \n");
                wordsIt++;
                if (wordsIt->compare(")") == 0) {
                    resultQuery += *wordsIt;
                    wordsIt++;
                }

            } else {

                if (wordsIt->compare("*") !=0 ) {
                    string tableD, fieldD;
                    getTableField(*wordsIt, tableD, fieldD, qm, tableMetaMap);
                    FieldMetadata * fmd =
                        tableMetaMap[tableD]->fieldMetaMap[fieldD];
                    resultQuery +=
                        fieldNameForQuery(tableMetaMap[tableD]->anonTableName,
                                          tableD, getNameForFilter(fmd,
                                                                   oDET),
                                          fmd->type, qm);
                    wordsIt++;
                    resultQuery += *wordsIt;
                    myassert(wordsIt->compare(
                                 ")") ==0,
                             "expected ) after field for COUNT \n");

                    wordsIt++;
                } else  {
                    resultQuery +=  *wordsIt;            //add *
                    wordsIt++;
                    resultQuery += *wordsIt;            // add )
                    assert_s(wordsIt->compare(
                                 ")") == 0,
                             " missing ) in count expression \n");
                    wordsIt++;
                }
            }

            resultQuery = resultQuery + processAlias(wordsIt, words);
            continue;

        }

        if (equalsIgnoreCase(*wordsIt,
                             "max") || equalsIgnoreCase(*wordsIt, "min")) {

            resultQuery = resultQuery + " " + *wordsIt +"( ";
            wordsIt++;
            assert_s(wordsIt->compare("(") == 0,
                     "missing ( in max/min expression\n");
            wordsIt++;

            string table2, field2;
            string realname = *wordsIt;
            getTableField(realname, table2, field2, qm, tableMetaMap);

            TableMetadata * tm = tableMetaMap[table2];
            FieldMetadata * fm = tm->fieldMetaMap[field2];

            assert_s(fm->type != TYPE_TEXT,
                     "min, max not fully implemented for text");

            string anonName =
                getOnionName(fm,oOPE);

            if (fm->isEncrypted) {
                if (DECRYPTFIRST) {
                    resultQuery = resultQuery + fieldNameForQuery(
                        tm->anonTableName, table2, field2, fm->type, qm);
                } else {
                    resultQuery = resultQuery + fieldNameForQuery(
                        tm->anonTableName, table2, anonName, fm->type, qm);
                }

                if (MULTIPRINC) {
                    resultQuery +=
                        mp->selectEncFor(table2, field2, qm, tmkm, tm,
                                         fm);
                }

                if (tableMetaMap[table2]->fieldMetaMap[field2]->secLevelOPE
                    ==
                    SEMANTIC_OPE) {
                    addIfNotContained(fullName(realname,
                                               table2), fieldsDec.OPEFields);
                }
            } else {
                resultQuery += *wordsIt;
            }

            resultQuery += ") ";

            wordsIt++;
            assert_s(wordsIt->compare(
                         ")") == 0, " missing ) in max expression \n");
            wordsIt++;
            LOG(edb) << "resultQuery before processAlias: " << resultQuery;
            resultQuery = resultQuery + processAlias(wordsIt, words);
            LOG(edb) << "resultQuery after processAlias: " << resultQuery;
            continue;
        }

        //must be field

        //cerr << "y\n";
        string origname = *wordsIt;
        getTableField(origname, table, field, qm, tableMetaMap);
        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];

        if (!DECRYPTFIRST) {
            //cerr <<"w\n";
            if (table.compare(oldTable)) {
                //need to add salt if new table is sensitive
                oldTable = table;
                if (tm->hasEncrypted && (!isSubquery)) {
                    resultQuery = resultQuery + " " + fieldNameForQuery(
                        tm->anonTableName, table, "salt", fm->type,
                        qm) + " ,";
                }
            }
        }

        if (!fm->isEncrypted) {
            resultQuery = resultQuery + " " + fieldNameForQuery(
                tm->anonTableName, table, field,fm->type,  qm) + processAlias(
                ++wordsIt, words);
            continue;
        }

        //encrypted field

        if (isSubquery) {
            resultQuery = resultQuery + " " +
                          fieldNameForQuery(
                tm->anonTableName, table,
                getOnionName(tm->fieldMetaMap[field], oDET), fm->type, qm);

            if (MULTIPRINC) {
                resultQuery += mp->selectEncFor(table, field, qm, tmkm, tm,
                                                fm);
            }

            if (tm->fieldMetaMap[field]->secLevelDET == SEMANTIC_DET) {
                addIfNotContained(fullName(field, table), fieldsDec.DETFields);
                addIfNotContained(fullName(field,
                                           table), fieldsDec.DETJoinFields);
            }
            if (tm->fieldMetaMap[field]->secLevelDET == DET) {
                addIfNotContained(fullName(field,
                                           table), fieldsDec.DETJoinFields);
            }
        } else {
            FieldMetadata * fm2 = tm->fieldMetaMap[field];
            if (detToAll && (fm2->secLevelDET == SEMANTIC_DET)) {
                addIfNotContained(fullName(field, table), fieldsDec.DETFields);
            }
            if (DECRYPTFIRST) {
                resultQuery = resultQuery + " " +
                              fieldNameForQuery(tm->anonTableName, table,
                                                field, fm2->type,
                                                qm);
            } else {
                resultQuery = resultQuery + " " +
                              fieldNameForQuery(tm->anonTableName, table,
                                                anonFieldNameForDecrypt(
                                                    fm2), fm2->type, qm);
            }
            if (MULTIPRINC) {
                resultQuery += mp->selectEncFor(table, field, qm, tmkm, tm,
                                                fm2);
            }
        }

        wordsIt++;
        resultQuery = resultQuery + processAlias(wordsIt, words);

    }

    assert_s(equalsIgnoreCase(*wordsIt,"from"), " expected FROM \n");
    resultQuery = resultQuery + " FROM ";

    wordsIt++;     //pass over "FROM"

    /**********************
     * from_body
     ***********************/

    //translate table names
    while ((wordsIt != words.end()) && (!isQuerySeparator(*wordsIt))) {
        if (wordsIt->compare("(")==0) {
            resultQuery += "(";
            wordsIt++;
        }
        assert_s(tableMetaMap.find(
                     *wordsIt) != tableMetaMap.end(), "table " + *wordsIt +
                 "does not exist");
        resultQuery = resultQuery + " " +
                      tableMetaMap[*wordsIt]->anonTableName;
        wordsIt++;
        resultQuery = resultQuery + processAlias(wordsIt, words);
    }

    list<string> res =
        processFilters(wordsIt, words, qm, resultQuery, fieldsDec, tmkm,
                       subqueries);

    tmkm.cleanup();
    qm.cleanup();

    return res;
}

//words are the keywords of expanded unanonymized queries
//words is unencrypted and unmodified query
static ResMeta
getResMeta(list<string> words, vector<vector<string> > & vals, QueryMeta & qm,
           map<string, TableMetadata * > & tm, MultiPrinc * mp,
           TMKM & tmkm)
{
    LOG(edb_v) << toString(words);

    ResMeta rm = ResMeta();

    size_t nFields = vals[0].size();
    rm.nFields = nFields;
    rm.nTuples = vals.size() - 1;

    //try to fill in these values based on the information in vals
    rm.isSalt = new bool[nFields];
    rm.table = new string[nFields];
    rm.field = new string[nFields];
    rm.o = new onion[nFields];
    rm.namesForRes = new string[nFields];
    rm.nTrueFields = 0;

    list<string>::iterator wordsIt;
    getFieldsItSelect(words, wordsIt);
    LOG(edb_v) << "nFields is " << nFields;

    bool ignore = false;

    for (unsigned int i = 0; i < nFields; i++) {

        //case : fields we added to help with multi princ enc
        if (ignore) {
            ignore = false;
            continue;
        }

        //case : salt
        if (isFieldSalt(vals[0][i])) {
            rm.isSalt[i] = true;
            rm.o[i] = oNONE;
            continue;
        }

        //case : fields requested by user

        rm.isSalt[i] =  false;
        rm.nTrueFields++;

        string currToken = *wordsIt;
        //cerr << "--> " << currToken << "\n";

        //subcase: aggregate
        if (isAgg(*wordsIt)) {
            //cerr << "before process agg \n";
            rm.namesForRes[i] =
                processAgg(wordsIt, words, rm.field[i], rm.table[i], rm.o[i],
                           qm,
                           tm,
                           0);
            if (MULTIPRINC) {
                mp->processReturnedField(i, fullName(rm.field[i],
                                                     rm.table[i]), rm.o[i],
                                         tmkm, ignore);
            }

//			cerr << "field, " << rm.field[i] << " table  " <<
// rm.table[i] << " onion " << rm.o[i] << " nameForRes " << rm.namesForRes[i]
// << "\n";
            continue;
        }

        //subcase: field
        LOG(edb_v) << "current field " << currToken;

        string table, field;
        getTableField(currToken, table, field, qm, tm);
        rm.table[i] = table;
        rm.field[i] = field;

        LOG(edb) << table << " " << field;
        if (tm[table]->fieldMetaMap[field]->isEncrypted) {
            if (tm[table]->fieldMetaMap[field]->INCREMENT_HAPPENED) {
                rm.o[i]= oAGG;
            } else {
                rm.o[i] = oDET;
            }
        } else {
            rm.o[i] = oNONE;
        }

        if (MULTIPRINC) {
            mp->processReturnedField(i, fullName(rm.field[i],
                                                 rm.table[i]), rm.o[i], tmkm,
                                     ignore);
        }

        wordsIt++;
        string alias = getAlias(wordsIt, words);

        if (alias.length() != 0) {
            rm.namesForRes[i] = alias;
        } else {
            rm.namesForRes[i] =  fieldNameForResponse(table, field, currToken,
                                                      qm);
        }

        processAlias(wordsIt, words);

    }

    LOG(edb_v) << "leaving get res meta";
    return rm;
}

static void
printRes(vector<vector<string> > & vals)
{
    LOG(edb) << "Raw results from the server to decrypt:";

    stringstream ssn;
    for (unsigned int i = 0; i < vals[0].size(); i++) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%-20s", vals[0][i].c_str());
        ssn << buf;
    }
    LOG(edb) << ssn.str();

    /* next, print out the rows */
    for (unsigned int i = 0; i < vals.size() - 1; i++) {
        stringstream ss;
        for (unsigned int j = 0; j < vals[i].size(); j++) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%-20s", vals[i+1][j].c_str());
            ss << buf;
        }
        LOG(edb) << ss.str();
    }
}

ResType *
EDBClient::rewriteDecryptSelect(const string &query, ResType * dbAnswer)
{

    //cerr << "in decrypt \n";

    //===== PREPARE METADATA FOR DECRYPTION ================

    //parse
    list<string> words = getSQLWords(query);

    QueryMeta qm = getQueryMeta(SELECT, words, tableMetaMap);

    expandWildCard(words, qm, tableMetaMap);

    vector<vector<string> > vals = *dbAnswer;

    if (VERBOSE) {printRes(vals); }

    TMKM tmkm;
    if (MULTIPRINC) {
        tmkm.processingQuery = false;
        // extracts enc-for principals from queries
        mp->prepareSelect(words, tmkm, qm, tableMetaMap);
    }

    ResMeta rm = getResMeta(words, vals, qm, tableMetaMap, mp, tmkm);

    //====================================================

    LOG(edb) << "done with res meta";

    //prepare the result
    ResType * rets = new ResType;
    rets = new vector<vector<string> >(rm.nTuples+1);

    size_t nFields = rm.nFields;
    size_t nTrueFields = rm.nTrueFields;

    //fill in field names
    rets->at(0) = vector<string>(nTrueFields);

    unsigned int index0 = 0;
    for (unsigned int i = 0; i < nFields; i++) {
        if ((!rm.isSalt[i]) && (!MULTIPRINC || tmkm.returnBitMap[i])) {
            rets->at(0).at(index0) = rm.namesForRes[i];
            index0++;
        }
    }

    for (unsigned int i = 0; i < rm.nTuples; i++)
    {
        rets->at(i+1) = vector<string>(nTrueFields);
        unsigned int index = 0;
        uint64_t salt = 0;

        for (unsigned int j = 0; j < nFields; j++) {

            if (rm.isSalt[j]) {             // this is salt
                LOG(edb) << "salt";
                salt = unmarshallVal(vals[i+1][j]);
                continue;
            }

            // ignore this field if it was requested additionally for multi
            // princ
            if (MULTIPRINC) {
                if (!tmkm.returnBitMap[j]) {
                    LOG(edb) << "ignore";
                    continue;
                }
            }

            // this is a value, we need to decrypt it

            string table = rm.table[j];
            string field = rm.field[j];

            LOG(edb) << fullName(field, table);

            if (rm.o[j] == oNONE) {             //not encrypted
                LOG(edb) << "its not enc";
                rets->at(i+1).at(index) = vals[i+1][j];
                index++;
                continue;
            }

            //the field is encrypted
            FieldMetadata * fm = tableMetaMap[table]->fieldMetaMap[field];

            string fullAnonName = fullName(getOnionName(fm,
                                                        rm.o[j]),
                                           tableMetaMap[table]->anonTableName);
            rets->at(i+
                     1).at(index) =
                crypt(vals[i+1][j], fm->type, fullName(field,
                                                       table),
                      fullAnonName,
                      getLevelForOnion(fm,
                                       rm.o[j]),
                      getLevelPlain(rm.o[j]), salt,
                      tmkm, vals[i+1]);

            index++;

        }
    }

    tmkm.cleanup();
    qm.cleanup();
    rm.cleanup();
    return rets;
}

string
EDBClient::processOperation(string operation, string op1, string op2,
                            QueryMeta & qm, string encryptedsubquery,
                            TMKM & tmkm)
throw (CryptDBError)
{

    string table1, field1, table2, field2;

    // fields are encrypted fields

    //the first operand is not a field
    if (!isField(op1)) {
        assert_s(Operation::isIN(
                     operation),
                 "only IN statements allowed to have constant on left");
        if (MULTIPRINC) {
            assert_s(false,
                     "MULTIPRINC first operand of operation should be field");
        }
        AES_KEY * aesKeyJoin =
            CryptoManager::get_key_DET(cm->getKey("join", DETJOIN));
        string res = "";
        res =
            marshallVal(cm->encrypt_DET((uint64_t) unmarshallVal(op1),
                                        aesKeyJoin)) + " IN " +
            encryptedsubquery + " ";
        return res;
    }

    // the first operand is a field

    getTableField(op1, table1, field1, qm, tableMetaMap);

    string anonTable1 = tableMetaMap[table1]->anonTableName;
    string anonField1, anonOp1;

    FieldMetadata * fm1 = tableMetaMap[table1]->fieldMetaMap[field1];

    fieldType ftype1 = fm1->type;

    string res = "";

    LOG(edb) << "operands " << op1 << " " << op2;
    if (isField(op1) && isField(op2)) {    //join
        LOG(edb_v) << "IN JOIN";
        if (MULTIPRINC) {
            assert_s(false, "join not supported in multi-user mode");
        }
        assert_s(Operation::isDET(
                     operation), "operation not supported with join");

        anonField1 = fm1->anonFieldNameDET;
        anonOp1 = fullName(anonField1, anonTable1);

        string table3, field3;
        getTableField(op2, table3, field3, qm, tableMetaMap);
        TableMetadata * tm2 = tableMetaMap[table3];
        FieldMetadata * fm2 = tm2->fieldMetaMap[field3];
        string anonTable2 = tm2->anonTableName;
        string anonField2 = fm2->anonFieldNameDET;
        string anonOp2 = fullName(anonField2, anonTable2);
        fieldType ftype2 = fm2->type;

        res =
            fieldNameForQuery(anonTable1, table1, anonField1, ftype1,
                              qm) + " " + operation + " " +
            fieldNameForQuery(anonTable2, table3, anonField2, ftype2,
                              qm) + " ";

        return res;
    }
    LOG(edb_v) << "NOT IN JOIN";

    if (Operation::isDET(operation)) {     //DET

        anonField1 = fm1->anonFieldNameDET;
        anonOp1 = fullName(anonField1, anonTable1);

        // TODO: this is inconsistent, I added some OPE fields with det
        // encryptions
        // you also may want to fetch ope only if there is an index on it

        SECLEVEL sl = fm1->secLevelDET;
        res = res + " " +
              fieldNameForQuery(anonTable1, table1, anonField1, ftype1,
                                qm) + " " +  operation + " ";

        if (Operation::isIN(operation)) {
            res = res + encryptedsubquery + " ";
            return res;
        }

        res = res + crypt(op2, ftype1, fullName(field1,
                                                table1), anonOp1, PLAIN_DET,
                          highestEq(sl), 0, tmkm);

        return res;

    }

    if (Operation::isILIKE(operation)) {     //DET

        /* Method 2 search: SWP */

        anonField1 = fm1->anonFieldNameSWP;
        string anonfull = fullName(anonField1,
                                   tableMetaMap[table1]->anonTableName);

        res += "search(" + anonField1 + ", ";

        Binary key = Binary(cm->getKey(mkey, anonfull, SWP));

        Token t = CryptoManager::token(key, Binary(removeApostrophe(op2)));

        res +=
            marshallBinary(string((char *)t.ciph.content,
                                  t.ciph.len)) + ", " +
            marshallBinary(string((char *)t.wordKey.content,
                                  t.ciph.len)) + ") ";

        return res;

        /*
         *
         * search method 1 code:
           anonField1 = fm1->anonFieldNameDET;
           anonOp1 = fullName(anonField1, anonTable1);

           anonTable1 = tableMetaMap[table1]->anonTableName;
           anonField1 = fm1->anonFieldNameDET;
           anonOp1 = fullName(anonField1, anonTable1);

           fieldType ftype = fm1->type;

           res = res + " search( ";

           assert_s(ftype == TYPE_TEXT, string(
                     "field ") + op1 + " has invalid type code " +
                 marshallVal((unsigned int)ftype));

           res = res + crypt(op2, ftype, fullName(field1,
                                               table1), anonOp1, PLAIN_DET,
                          DET, 0, tmkm);

           res = res + ", " + anonOp1 + ") ";

           return res;
         */

    }

    //operation is OPE

    anonField1 = tableMetaMap[table1]->fieldMetaMap[field1]->anonFieldNameOPE;
    anonOp1 = fullName(anonField1, anonTable1);

    FieldMetadata * fm = tableMetaMap[table1]->fieldMetaMap[field1];

    assert_s(Operation::isOPE(
                 operation), " expected OPE , I got " + operation + " \n");

    string fieldname;
    if (DECRYPTFIRST) {
        fieldname = fieldNameForQuery(anonTable1, table1, field1, ftype1, qm);
    } else {
        fieldname = fieldNameForQuery(anonTable1, table1, anonField1, ftype1,
                                      qm);
    }

    //cout << "key used to get to OPE level for "<< tokenOperand << "is " <<
    //  CryptoManager::marshallKey(cm->getKey(tokenOperand, OPESELF)) << "\n";
    res = res + " " + fieldname + " " +  operation + " " +
          crypt(op2, fm->type, fullName(field1, table1),
                anonOp1, PLAIN_OPE, OPESELF, 0, tmkm);

    return res;
}

list<string>
EDBClient::rewriteEncryptDrop(const string &queryI)
throw (CryptDBError)
{
    //handles queries of the form DROP TABLE tablename;
    char *query = strdup(queryI.c_str());

    const char delimiters[7]={' ', ')', '(', ';', ',','\n',  '\0'};

    string tableName = strtok(query, delimiters);
    tableName = strtok(NULL, delimiters);
    tableName = strtok(NULL, delimiters);
    free(query);

    //prepare anonymized query for the server
    string result = "DROP TABLE ";

    assert_s(tableMetaMap.find(
                 tableName) != tableMetaMap.end(),
             "the table to be deleted does not exist\n");

    string anonTableName = tableMetaMap[tableName]->anonTableName;

    result = result + anonTableName + ";";

    //cout << result << "\n\n";
    //delete associated data from internal data structures
    tableMetaMap.erase(tableName);
    tableNameMap.erase(anonTableName);

    list<string> resultList;
    resultList.push_back(result.c_str());
    return resultList;
}

list<string>
EDBClient::rewriteEncryptDelete(const string &query)
throw (CryptDBError)
{

    /***********************
     * QUERY looks like: DELETE FROM from_body WHERE where_body;
     *
     * -- resultQuery will hold the translated query
     * -- the result of this function holds all the decryption queries needed
     *    and resultQuery
     **********************/

    list<string> words = getSQLWords(query);

    if (MULTIPRINC) {
        if (mp->checkPsswd(DELETE, words)) {
            return list<string>();
        }
    }

    //first figure out what tables are involved to know what fields refer to
    QueryMeta qm = getQueryMeta(DELETE, words, tableMetaMap);

    TMKM tmkm;
    if (MULTIPRINC) {
        tmkm.processingQuery = true;
        mp->getEncForFromFilter(DELETE, words, tmkm, qm, tableMetaMap);
    }

    list<string>::iterator wordsIt = words.begin();

    assert_s(equalsIgnoreCase(*wordsIt,
                              "delete"), "first token is not DELETE\n");
    wordsIt++;

    assert_s(toLowerCase(*wordsIt).compare(
                 "from") == 0,
             "second token of a DELETE statement is not FROM \n");
    wordsIt++;

    string resultQuery = "DELETE FROM ";

    /**********************
     * from_body
     ***********************/
    //translate table names
    while (!((wordsIt == words.end()) ||
             (equalsIgnoreCase(*wordsIt, "where")))) {
        string table = *wordsIt;
        assert_s(tableMetaMap.find(
                     table) != tableMetaMap.end(), "table does not exist");
        resultQuery = resultQuery + " " +
                      tableMetaMap[table]->anonTableName + processAlias(
            ++wordsIt, words);
    }

    FieldsToDecrypt ftd;
    list<string> res =
        processFilters(wordsIt, words, qm, resultQuery, ftd,
                       tmkm);

    tmkm.cleanup();
    qm.cleanup();

    return res;
}

string
EDBClient::processValsToInsert(string field, string table, uint64_t salt,
                               string value,
                               TMKM & tmkm)
{

    FieldMetadata * fm = tableMetaMap[table]->fieldMetaMap[field];

    if (!fm->isEncrypted) {
        return value;
    }

    if (DECRYPTFIRST) {
        string fullname = fullName(field, table);
        fieldType type = fm->type;
        string anonTableName = tableMetaMap[table]->anonTableName;

        if (type == TYPE_INTEGER) {
            if (equalsIgnoreCase(value,"null")) {value = "0"; }
            AES_KEY * key = CryptoManager::get_key_DET(dec_first_key);
            string res =
                marshallVal(CryptoManager::encrypt_DET(unmarshallVal(value),
                                                       key));
            return res;
        } else {
            if (equalsIgnoreCase(value,"null")) {value = " "; }
            assert_s(type == TYPE_TEXT, "given unexpected type");
            AES_KEY * key = CryptoManager::get_key_SEM(dec_first_key);
            string ptext = removeApostrophe(value);
            string cipher = CryptoManager::encrypt_SEM(ptext, key, 0);
            return marshallBinary(cipher);
        }
    }

    string res =  "";

    string fullname = fullName(field, table);

    string anonTableName = tableMetaMap[table]->anonTableName;

    if (equalsIgnoreCase(value,"null")) {
        if (fm->exists(fm->anonFieldNameOPE)) {
            res += ", NULL ";
        }
        if (fm->exists(fm->anonFieldNameAGG)) {
            res += ", " +
                   marshallBinary(BytesFromInt(1,
                                               CryptoManager::
                                               Paillier_len_bytes));
        }
        if (fm->has_search) {
            res += ", NULL ";
        }
    } else {

        res +=  " " +
               crypt(value, fm->type, fullname,
                     fullName(fm->anonFieldNameDET,
                              anonTableName), PLAIN_DET, fm->secLevelDET,
                     salt, tmkm);

        LOG(edb_v) << "just added key from crypt";

        if (fm->exists(fm->anonFieldNameOPE)) {
            res += ", " +
                   crypt(value, fm->type, fullname,
                         fullName(fm->anonFieldNameOPE,
                                  anonTableName), PLAIN_OPE, fm->secLevelOPE,
                         salt, tmkm);

        }

        if (fm->exists(fm->anonFieldNameAGG)) {
            res += ", " +
                   crypt(value, fm->type, fullname,
                         fullName(fm->anonFieldNameAGG,
                                  anonTableName), PLAIN_AGG, SEMANTIC_AGG,
                         salt, tmkm);
        }

        if (fm->has_search) {
            res += ", " +
                   crypt(value, fm->type, fullname,
                         fullName(fm->anonFieldNameSWP,
                                  anonTableName), PLAIN_SWP, SWP,
                         salt, tmkm);
        }

    }

    return res;

}

string
EDBClient::getInitValue(string field, string table, AutoInc * ai)
{

    TableMetadata * tm = tableMetaMap[table];

    FieldMetadata * fm = tm->fieldMetaMap[field];

    //check if field has autoinc
    if (tm->autoIncField == field) {
        //has autoinc
        assert_s(
            ai != NULL,
            "Current field has autoinc, but the autoincrement value was not supplied ");
        return StringFromVal(ai->incvalue + 1);
    }

    // use the default value
    // TODO: record default values
    if (fm->type == TYPE_INTEGER) {
        return "0";
    } else {
        return "''";
    }

}

list<string>
EDBClient::rewriteEncryptInsert(const string &query, AutoInc * ai)
throw (CryptDBError)
{

    list<string> words = getSQLWords(query);

    TMKM tmkm;

    //struct timeval starttime, endtime;
    //gettimeofday(&starttime, NULL);
    if (MULTIPRINC) {
        tmkm.processingQuery = true;
        //if this is the fake table providing user passwords, ignore query
        if (mp->checkPsswd(INSERT, words)) {
            //gettimeofday(&endtime, NULL);
            //cerr << "insert passwd took " << timeInMSec(starttime, endtime)
            // << "\n";
            return list<string>();
        }
    }

    list<string>::iterator wordsIt = words.begin();

    string resultQuery = "";

    //go over "insert into"
    roll<string>(wordsIt, 2);
    resultQuery = resultQuery + "INSERT INTO ";

    //table name
    string table = *wordsIt;

    assert_s(tableMetaMap.find(
                 table)!= tableMetaMap.end(), "table " + table +
             " does not exist");

    TableMetadata * tm = tableMetaMap[table];

    resultQuery = resultQuery + tableMetaMap[table]->anonTableName + " ";
    roll<string>(wordsIt, 1);

    std::set<string> fieldsIncluded;
    list<string> fields;
    list<string> fieldsToAdd;
    list<string> princsToAdd;
    list<string>::iterator addit;
    list<string> overallFieldNames;

    size_t noFieldsGiven = 0;

    if (wordsIt->compare("(") == 0) {
        //new order for the fields
        resultQuery = resultQuery + " (  ";

        if (!DECRYPTFIRST) {
            if (tableMetaMap[table]->hasEncrypted) {
                resultQuery += " salt, ";
            }
        }

        wordsIt++;

        while (wordsIt->compare(")") != 0) {
            fields.push_back(*wordsIt);
            fieldsIncluded.insert(*wordsIt);
            resultQuery = resultQuery + " " + processInsert(*wordsIt, table,
                                                            tm);
            wordsIt++;
            resultQuery += " " + checkStr(wordsIt, words, ",", ")");
        }

        // the user may not provide all fields in an insertion, expecting
        // these to default
        // if some are encrypted fields we need to provide the encryption of
        // default
        // if some of these are principals, we need to provide the next
        // increment value
        noFieldsGiven = fields.size();

        for (addit = tm->fieldNames.begin(); addit!=tm->fieldNames.end();
             addit++) {
            if (fieldsIncluded.find(*addit) == fieldsIncluded.end()) {
                if (tm->fieldMetaMap[*addit]->isEncrypted)  {
                    fieldsToAdd.push_back(*addit);
                }
                if (MULTIPRINC) {

                    if (mp->isPrincipal(fullName(*addit, table))) {
                        LOG(edb_v) << "add to princs " << *addit;
                        princsToAdd.push_back(*addit);
                    }
                }

            }
        }

        //add fields names from fieldsToAdd
        for (addit = fieldsToAdd.begin(); addit != fieldsToAdd.end();
             addit++) {
            resultQuery += ", " + processInsert(*addit, table, tm);
            fields.push_back(*addit);
        }

        if (MULTIPRINC) {
            //add fields names from princsToAdd
            for (addit = princsToAdd.begin(); addit != princsToAdd.end();
                 addit++) {
                resultQuery += ", " + processInsert(*addit, table, tm);
                fields.push_back(*addit);
            }
        }

        resultQuery = resultQuery + " ) ";
        wordsIt++;         //go over )

    } else {
        fields = tableMetaMap[table]->fieldNames;
        noFieldsGiven = fields.size();
    }

    //go over VALUES
    assert_s(equalsIgnoreCase(*wordsIt, "values"), "expected values");
    wordsIt++;
    resultQuery = resultQuery + " VALUES ";

    while (wordsIt != words.end()) {
        wordsIt++;
        resultQuery += " ( ";

        //collect all values in vals

        list<string> vals;
        list<string>::iterator fieldIt = fields.begin();

        //add encryptions of the fields
        for (unsigned int i = 0; i < noFieldsGiven; i++) {
            vals.push_back(*wordsIt);
            wordsIt++;
            checkStr(wordsIt, words, ",",")");
        }
        //we now need to add fields from fieldsToAdd
        for (addit = fieldsToAdd.begin(); addit != fieldsToAdd.end();
             addit++) {
            string field = *addit;
            string val = getInitValue(field, table, ai);
            vals.push_back(val);
        }

        if (MULTIPRINC) {
            //we now need to add fields from princsToAdd
            for (addit = princsToAdd.begin(); addit != princsToAdd.end();
                 addit++) {
                string field = *addit;
                vals.push_back(getInitValue(table, field));
            }

            //insert any new hasaccessto instances
            LOG(edb_v) << "before insert relations";
            mp->insertRelations(vals, table, fields, tmkm);
        }

        LOG(edb_v) << "noFieldsGiven " << noFieldsGiven;
        LOG(edb_v) << "fiels have " << fields.size();
        LOG(edb_v) << "vals have " << vals.size();

        uint64_t salt = 0;

        if (!DECRYPTFIRST) {
            if (tableMetaMap[table]->hasEncrypted) {
                //rand field
                salt =  randomValue();
                resultQuery =  resultQuery + marshallVal(salt) + ", ";
            }
        }

        list<string>::iterator valIt = vals.begin();
        fieldIt = fields.begin();

        //add encryptions of the fields
        for (unsigned int i = 0; i < noFieldsGiven; i++) {
            string fieldName = *fieldIt;
            string value = removeApostrophe(*valIt);

            if (MULTIPRINC) {
                string fullname = fullName(fieldName, table);
                //FIX AUTOINC
                /*if (isPrincipal(fullname, accMan, mkm)) {
                        if (autoInc.find(fullname) == autoInc.end()) {
                                LOG(edb_v) << "before unmarshallVal";
                                autoInc[fullname] = unmarshallVal(value);
                                rb.autoinc = marshallVal(autoInc[fullname]);
                                LOG(edb_v) << "after unmar val";
                        } else {
                                LOG(edb_v) << "before unmar val";
                                autoInc[fullname] = max(autoInc[fullname],
                                   unmarshallVal(value));
                                rb.autoinc = marshallVal(autoInc[fullname]);
                                LOG(edb_v) << "rb autoinc is now " <<
                                   rb.autoinc;
                        }
                   }*/
            }

            //cerr << "processing for field " << *fieldIt << " with given
            // value " << *valIt << "\n";
            resultQuery += processValsToInsert(*fieldIt, table, salt,  *valIt,
                                               tmkm);
            valIt++;
            fieldIt++;
            if (i < noFieldsGiven-1) {
                resultQuery += ", ";
            }
        }

        //we now need to add fields from fieldsToAdd
        for (addit = fieldsToAdd.begin(); addit != fieldsToAdd.end();
             addit++) {
            string field = *addit;
            string val = *valIt;
            valIt++;
            resultQuery += ", " + processValsToInsert(field, table, salt, val,
                                                      tmkm);
        }

        if (MULTIPRINC) {
            //we now need to add fields from princsToAdd
            for (addit = princsToAdd.begin(); addit != princsToAdd.end();
                 addit++) {
                string field = *addit;
                string fullname = fullName(field, table);
                string val = *valIt;
                valIt++;
                resultQuery += ", " +
                               processValsToInsert(field, table, salt, val,
                                                   tmkm);
            }
        }

        assert_s(valIt == vals.end(), "valIt should have been the end\n");
        vals.clear();

        assert_s(wordsIt->compare(")") == 0, "missing )");
        resultQuery += ")";
        wordsIt++;

        resultQuery += checkStr(wordsIt, words, ",", ")");

    }

    assert_s(wordsIt == words.end(), "invalid text after )");

    resultQuery = resultQuery + ";" + '\0';

    tmkm.cleanup();

    return list<string>(1, resultQuery);
}

list<string>
EDBClient::rewriteEncryptCommit(const string &query)
throw (CryptDBError)
{

    list<string> words = getSQLWords(query);

    list<string>::iterator wordsIt = words.begin();

    wordsIt++;

    if (MULTIPRINC) {
        if (equalsIgnoreCase(*wordsIt, "annotations")) {
            wordsIt++;
            assert_s(
                wordsIt == words.end(),
                "nothing should come after <commit annotations>");
            mp->commitAnnotations();
            return list<string>();
        }
    }

    return list<string>(1, "commit;");
}

list<string>
EDBClient::rewriteEncryptBegin(const string &query)
throw (CryptDBError)
{
    return list<string>(1, "begin;");
}

list<string>
EDBClient::rewriteEncryptAlter(const string &query)
throw (CryptDBError)
{

    assert_s(false, "alter needs revision -- look at lower casing as well");

    /* *
     * alter table customer add constraint pk_customer
     * primary key (c_w_id, c_d_id, c_id);
     */
    string resultQuery = "";

    list<string> words = getSQLWords(query);

    list<string>::iterator wordsIt = words.begin();

    assert_s(wordsIt->compare("alter") == 0, "expected alter");
    wordsIt++;
    resultQuery = resultQuery + "alter ";

    assert_s(wordsIt->compare("table") == 0, "expected table");
    wordsIt++;
    resultQuery = resultQuery  + "table ";

    string table = *wordsIt;
    assert_s(isTable(table, tableMetaMap),  "not a valid table");
    TableMetadata * tm = tableMetaMap[table];
    resultQuery = resultQuery + tm->anonTableName;
    wordsIt++;

    assert_s(wordsIt->compare("add") == 0, "expected 'add'");
    wordsIt++;
    resultQuery = resultQuery  + " add ";

    assert_s(wordsIt->compare("constraint") == 0, "expected 'constraint'");
    wordsIt++;
    resultQuery = resultQuery  + "constraint ";

    resultQuery = resultQuery + *wordsIt + " ";
    wordsIt++;

    assert_s(wordsIt->compare("primary") == 0, "expected 'primary'");
    wordsIt++;
    resultQuery = resultQuery  + "primary ";

    assert_s(wordsIt->compare("key") == 0, "expected 'key'");
    wordsIt++;
    resultQuery = resultQuery  + "key ";

    assert_s(wordsIt->compare("(") == 0, "expected (");
    wordsIt++;
    resultQuery = resultQuery  + "( ";

    FieldsToDecrypt fd;

    while ((wordsIt != words.end()) && (wordsIt->compare(")") != 0)) {
        string fieldName = *wordsIt;

        string anonfieldName = getOnionName(
            tableMetaMap[table]->fieldMetaMap[fieldName], oDET);

        tm->primaryKey.push_back(fieldName);

        resultQuery = resultQuery + anonfieldName + " ,";

        wordsIt++;
        checkStr(wordsIt, words, ",", ")");
    }

    assert_s(wordsIt != words.end(), "unexpected end of query: missing )");
    assert_s(wordsIt->compare(")") == 0, "missing )");
    resultQuery[resultQuery.length()-1] = ' ';
    resultQuery = resultQuery + ")";
    wordsIt++;

    assert_s(
        wordsIt == words.end(), "expected end of query, but it continues " );

    return list<string>(1, resultQuery);
}

//returns true if this query has to do with cryptdb
// e.g. SET NAMES 'utf8' is a negative example
static bool
considerQuery(command com, const string &query)
{

    switch (com) {
    case CREATE: {
        list<string> words = getSQLWords(query);
        list<string>::iterator wordsIt = words.begin();
        wordsIt++;
        if (equalsIgnoreCase(*wordsIt, "function")) {
            return false;
        }
        break;
    }
    case UPDATE: {break; }
    case INSERT: {
        list<string> words = getSQLWords(query);
        if (contains("select", words)) {
            LOG(warn) << "given nested query!";
            return false;
        }
        break;
    }
    case SELECT: {
        list<string> words = getSQLWords(query);
        //for speed
        /*if ((!contains("from", words)) && (!contains("FROM", words))) {
                if (VERBOSE_V) { cerr << "does not contain from";}
                return false;
           }*/
        break;
    }
    case DROP: {
        list<string> words = getSQLWords(query);
        list<string>::iterator wordsIt = words.begin();
        wordsIt++;
        if (equalsIgnoreCase(*wordsIt, "function")) {
            return false;
        }
        break;
    }
    case DELETE: {break; }
    case BEGIN: {
        LOG(edb_v) << "begin";
        if (DECRYPTFIRST) {
            return true;
        }
        return false;
    }
    case COMMIT: {
        if (DECRYPTFIRST) {
            return true;
        }
        list<string> words = getSQLWords(query);
        list<string>::iterator wordsIt = words.begin();
        wordsIt++;
        if (equalsIgnoreCase(*wordsIt, "annotations")) {
            return true;
        }
        LOG(edb_v) << "commit";
        return false;
    }
    case ALTER: {
        LOG(edb_v) << "alter";
        if (DECRYPTFIRST) {
            return true;
        }

        return false;
    }
    default:
    case OTHER: {
        LOG(edb_v) << "other";
        return false;
    }
    }

    return true;
}

list<string>
EDBClient::rewriteEncryptQuery(const string &query, AutoInc * ai)
throw (CryptDBError)
{
    if (!isSecure)
        return list<string>(1, query);

    //It is secure

    command com = getCommand(query);

    //some queries do not need to be encrypted
    if (!considerQuery(com, query)) {
        if (VERBOSE) { cerr << "query not considered \n"; }
        list<string> res;
        res.push_back(query);
        if (VERBOSE) { cerr << "returning query " << query << "\n"; }
        return res;
    }

    //dispatch query to the appropriate rewriterEncryptor
    switch (com) {
    case CREATE: {return rewriteEncryptCreate(query); }
    case UPDATE: {return rewriteEncryptUpdate(query); }
    case INSERT: {return rewriteEncryptInsert(query, ai); }
    case SELECT: {return rewriteEncryptSelect(query); }
    case DROP: {return rewriteEncryptDrop(query); }
    case DELETE: {return rewriteEncryptDelete(query); }
    case BEGIN: {
        if (DECRYPTFIRST)
            return list<string>(1, query);

        return rewriteEncryptBegin(query);
    }
    case COMMIT: {
        if (DECRYPTFIRST)
            return list<string>(1, query);

        return rewriteEncryptCommit(query);
    }
    case ALTER: {
        if (DECRYPTFIRST)
            return list<string>(1, query);

        return rewriteEncryptAlter(query);
    }
    case OTHER:
    default: {
        cerr << "other query\n";
        if (DECRYPTFIRST)
            return list<string>(1, query);
    }
    }
    cerr << "e" << endl;
    assert_s(false, "invalid control path");
    return list<string>();
}

ResType *
EDBClient::decryptResults(const string &query, ResType * dbAnswer)
{
    if (DECRYPTFIRST)
        return dbAnswer;

    if (dbAnswer->size() == 0)
        return dbAnswer;

    // some queries do not need to be encrypted
    command com = getCommand(query);
    if (!considerQuery(com, query)) {
        if (VERBOSE) { cerr << "do not consider \n"; }
        return dbAnswer;
    }

    switch (com) {
    case SELECT:
        return rewriteDecryptSelect(query, dbAnswer);

    default:
        return dbAnswer;
    }
}

void
EDBClient::dropTables()
{

    if (dropOnExit) {
        map<string, TableMetadata *>::iterator it = tableMetaMap.begin();

        for (; it != tableMetaMap.end(); it++) {

            if (VERBOSE) {cerr<< "drop table " << it->first << "\n"; }
            conn->execute("DROP TABLE " + it->second->anonTableName + " ;");
        }
    }
}

ResType *
EDBClient::decryptResultsWrapper(const string &query, DBResult * dbres)
{
    command comm = getCommand(query);

    if (comm == SELECT) {
        LOG(edb) << "going in select";
        ResType * rets = decryptResults(query, dbres->unpack());

        if (VERBOSE) {
            LOG(edb_v) << "Decrypted results:";

            for (unsigned int i = 0; i < rets->size(); i++) {
                stringstream ss;
                for (unsigned int j = 0; j < rets->at(i).size(); j++) {
                    char buf[256];
                    snprintf(buf, sizeof(buf), "%-30s", rets->at(i).at(
                                 j).c_str());
                    ss << buf;
                }
                LOG(edb_v) << ss.str();
            }
        }

        return rets;
    }

    LOG(edb) << "return empty results";
    //empty result
    return new ResType();

}

ResType *
EDBClient::execute(const string &query)
{
    DBResult * res = 0;

    LOG(edb_v) << "Query: " << query;

    if (!isSecure) {

        if (!conn->execute(query, res)) {
            fprintf(stderr, "%s failed: %s \n", query.c_str(), conn->getError(
                        ).c_str());
            return NULL;
        }

        if (getCommand(query) == SELECT) {
            ResType *r = res->unpack();
            delete res;
            return r;
        } else {
            delete res;
            return new ResType();
        }
    }

    //secure

    list<string> queries;
    AutoInc * ai = new AutoInc();

    try {
        queries = rewriteEncryptQuery(query, ai);
    } catch (CryptDBError se) {
        LOG(warn) << "problem with query " << query << " " << se.msg;
        return NULL;
    }

    if (queries.size() == 0) {
        return new ResType();
    }

    auto queryIt = queries.begin();

    size_t noQueries = queries.size();
    size_t counter = 0;

    LOG(edb_v) << "Translated queries:";

    for (; queryIt != queries.end(); queryIt++) {
        counter++;

        LOG(edb_v) << *queryIt;

        DBResult * reply;
        reply = NULL;

        struct timeval t0, t1;
        if (VERBOSE)
            gettimeofday(&t0, 0);

        if (!conn->execute(*queryIt, reply)) {
            LOG(warn) << "query " << *queryIt << "failed";
            return NULL;
        }

        if (VERBOSE) {
            gettimeofday(&t1, 0);
            uint64_t us = t1.tv_usec - t0.tv_usec +
                          (t1.tv_sec - t0.tv_sec) * 1000000;
            LOG(edb_v) << "query latency: " << us << " usec";
        }

        if (counter < noQueries) {
            delete reply;
            //do nothing

        } else {
            assert_s(counter == noQueries, "counter differs from noQueries");

            LOG(edb) << "onto decrypt results";
            ResType * rets;
            try {

                //remove
                //cerr << "dec\n";
                //rets = new vector<vector<string> >(1);
                //rets->at(0)=vector<string>(1);
                //rets->at(0).at(0) = "1";
                rets = decryptResultsWrapper(query, reply);
            } catch (CryptDBError e) {
                cerr << e.msg;
                queries.clear();
                delete reply;
                return NULL;
            }

            LOG(edb) << "done with decrypt results";
            queries.clear();
            delete reply;
            return rets;

        }

    }

    assert_s(false, "invalid control path");

    return new ResType();
}

void
EDBClient::exit()
{
    LOG(edb_v) << "Exiting..";

    if (isSecure) {
        dropAll(conn);

        if (dropOnExit) {
            dropTables();

        }

        LOG(edb_v) << "DROP FUNCTIONS;";
    }
}

static void
cleanup(map<string, TableMetadata *> & tableMetaMap)
{
    //todo
}

EDBClient::~EDBClient()
{

    //cleanup data structures
    tableNameMap.clear();
    cleanup(tableMetaMap);
    cm->~CryptoManager();
    delete mp;
}

static string
getQuery(ifstream & createsFile)
{
    string line = "";
    string query = "";
    while ((!createsFile.eof()) && (line.find(';') == string::npos)) {
        getline(createsFile, line);
        query = query + line;
    }
    return query;

}

int
EDBClient::train(string queryFile)
throw (CryptDBError)
{
    ifstream infile(queryFile.c_str());

    if (!infile.is_open()) {
        cerr << "could not open file " << queryFile << "\n";
        return -1;
    }

    isTraining = true;

    string query;
    list<string> queries;
    while (!infile.eof()) {
        query = getQuery(infile);

        if (query.length() == 0) {
            continue;
        }

        if (query.length() > 0) {
            queries = rewriteEncryptQuery(string(query+";"));
        }
    }

    isTraining = false;

    return 0;
}

int
EDBClient::train_finish()
throw (CryptDBError)
{

    map<string, TableMetadata *>::iterator it = tableMetaMap.begin();
    map<string, FieldMetadata *>::iterator fieldIt;

    for (; it != tableMetaMap.end(); it++) {
        TableMetadata * tm = it->second;

        for (fieldIt = tm->fieldMetaMap.begin();
             fieldIt != tm->fieldMetaMap.end(); fieldIt++) {
            FieldMetadata * fm = fieldIt->second;

            cerr << fieldIt->first << " ";

            if (!fm->ope_used) {
                tm->fieldNameMap.erase(fm->anonFieldNameOPE);
                fm->anonFieldNameOPE = "";
            } else {
                cerr << " OPE ";

            }
            if (!fm->agg_used) {
                tm->fieldNameMap.erase(fm->anonFieldNameAGG);
                fm->anonFieldNameAGG = "";
            } else {
                cerr << " AGG ";
            }

            if (fm->secLevelDET == SEMANTIC_DET) {
                cerr << " sem ";
            } else {
                cerr << " det ";
            }

            cerr << "\n";

        }

    }
    return 0;

}

int
EDBClient::create_trained_instance(bool submit)
throw (CryptDBError)
{

    string query;

    //===========CREATE TABLES =================//

    map<string, TableMetadata *>::iterator it = tableMetaMap.begin();

    for (; it != tableMetaMap.end(); it++) {
        TableMetadata * tm = it->second;

        query = "CREATE TABLE " + tm->anonTableName + " ( salt "+ TN_I64 +
                ", ";

        list<string>::iterator fieldIt = tm->fieldNames.begin();

        for (; fieldIt != tm->fieldNames.end(); fieldIt++) {
            FieldMetadata * fm = tm->fieldMetaMap[*fieldIt];
            switch (fm->type) {
            case TYPE_INTEGER: {
                query = query + " " + fm->anonFieldNameDET + " "+ TN_I64 +
                        ",";
                if (fm->exists(fm->anonFieldNameOPE)) {
                    query = query + " " + fm->anonFieldNameOPE + " "+
                            TN_I64 + ",";
                }
                if (fm->exists(fm->anonFieldNameAGG)) {
                    query = query + " " + fm->anonFieldNameAGG + " "+TN_HOM+
                            " ,";
                }
                break;
            }
            case TYPE_TEXT: {
                query = query + " " + fm->anonFieldNameDET + "  "+TN_TEXT +
                        " ,";
                if (fm->exists(fm->anonFieldNameOPE)) {
                    query = query + " " + fm->anonFieldNameOPE + " "+
                            TN_I64 + ",";
                }

                break;
            }
            default: {assert_s(false,
                               "invalid type in create_trained_instance"); }
            }
        }
        query[query.length()-1] = ' ';
        query = query + ");";

        cerr << query << "\n";
        if (submit)
            conn->execute(query);
    }

    //============CREATE INDEXES AND KEYS ================//

    it = tableMetaMap.begin();

    for (; it != tableMetaMap.end(); it++) {
        TableMetadata * tm = it->second;

        //primary keys
        if (tm->primaryKey.size() > 0) {

            list<string>::iterator primIt = tm->primaryKey.begin();

            string detlist = "";
            string opelist = "";

            for (; primIt != tm->primaryKey.end(); primIt++) {
                FieldMetadata * fm = tm->fieldMetaMap[*primIt];

                if (fm->exists(fm->anonFieldNameOPE)) {
                    if (opelist.length() > 0) {
                        cerr << "second ope in primary key for table " +
                        it->first + " \n";
                        opelist = opelist + fm->anonFieldNameDET + " ,";
                    } else {
                        opelist = detlist + fm->anonFieldNameOPE + " ,";
                    }
                } else {
                    if (opelist.length() > 0) {
                        opelist = opelist +  fm->anonFieldNameDET + " ,";
                    }
                }
                detlist = detlist +  fm->anonFieldNameDET + " ,";
            }

            detlist[detlist.length() - 1] = ' ';
            string pk_query = "ALTER TABLE " + tm->anonTableName +
                              " add constraint con_" + tm->anonTableName +
                              " primary key ( " +
                              detlist + ");";
            cerr << pk_query << "\n";
            if (submit)
                conn->execute(pk_query);

            if (opelist.length() > 0) {
                opelist[opelist.length() - 1] = ' ';
                string pk_ope_query = "CREATE INDEX inpk_" +
                                      tm->anonTableName +  " on " +
                                      tm->anonTableName + " (" +
                                      opelist + ");";
                if (submit)
                    conn->execute(pk_ope_query);

                cerr << pk_ope_query << "\n";
            }

        }

        //indexes
        if (tm->indexes.size() > 0) {

            list<IndexMetadata *>::iterator indexIt = tm->indexes.begin();

            for (; indexIt != tm->indexes.end(); indexIt++) {
                IndexMetadata * im = *indexIt;

                string index_query = "create ";
                if (im->isUnique) {
                    index_query = index_query + " unique ";
                }

                index_query = index_query + " index " + im->anonIndexName +
                              " on " + tm->anonTableName + " ( ";

                list<string>::iterator fieldIt = im->fields.begin();
                for (; fieldIt != im->fields.end(); fieldIt++) {
                    index_query = index_query +
                                  tm->fieldMetaMap[*fieldIt]->
                                  anonFieldNameDET + " ,";
                }

                index_query[index_query.length()-1] = ' ';
                index_query = index_query + ");";
                cerr << index_query << "\n";
                if (submit)
                    conn->execute(index_query);
            }
        }

    }

    return 0;

}

void
EDBClient::outputOnionState()
{
    for (map<string, TableMetadata *>::iterator tm = tableMetaMap.begin();
         tm != tableMetaMap.end(); tm++) {
        if (tm->second->hasEncrypted) {
            for (map<string, FieldMetadata *>::iterator fm =
                     tm->second->fieldMetaMap.begin();
                 fm != tm->second->fieldMetaMap.end(); fm++) {
                FieldMetadata * f = fm->second;
                if (f->isEncrypted) {
                    printf("%-36s", fullName(f->fieldName, tm->first).c_str());
                    printf(" %-14s", levelnames[f->secLevelDET].c_str());
                    if (FieldMetadata::exists(f->anonFieldNameOPE))
                        printf(" %-14s", levelnames[f->secLevelOPE].c_str());
                    cout << "\n";
                }
            }
        }
    }
}

string
EDBClient::crypt(string data, fieldType ft, string fullname,
                 string anonfullname,
                 SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                 //optional, for MULTIPRINC
                 TMKM & tmkm,
                 const vector<string> & res)
{

    LOG(crypto) << "crypting data " << data
                << " type " << ft
                << " fullname " << fullname
                << " anonfullname " << anonfullname
                << " fromlevel " << fromlevel
                << " tolevel " << tolevel
                << " salt " << salt;

    if (DECRYPTFIRST) {
        // we don't encrypt values, and they come back decrypted
        return data;
    }

    // for the parsing-only experiment
    if (PARSING) {
        //cerr << "crypt given " << data << " len " << data.length() << "\n";

        assert_s(data.length() != 0, "data to crypt has zero length");
        if (removeApostrophe(data).length() == 0) {
            return data;
        }
        if ((ft == TYPE_TEXT) && (fromlevel > tolevel)) {
            string aux = unmarshallBinary(data);
            data = aux;
        }
        //cerr << "crypt returns " << data << "\n";
        return data;
    }

    if (MULTIPRINC) {
        if (tmkm.processingQuery) {
            string key = mp->get_key(fullname, tmkm);
            cm->setMasterKey(key);
            if (VERBOSE_V) {
                // cerr<<"++> crypting " << anonfullname << " contents " <<
                // data << " fromlevel " << fromlevel;
                // cerr<< " tolevel " << tolevel << " salt " << salt << " key
                // "; myPrint(key, AES_KEY_BYTES);
            }
            //cerr << "++> crypting " << data << " with key "; myPrint(key,
            // AES_KEY_BYTES); cerr << "\n";

        } else {
            string key = mp->get_key(fullname, tmkm, res);
            cm->setMasterKey(key);
            if (VERBOSE_V) {
                // cerr<<"++> crypting " << anonfullname << " contents " <<
                // data << " fromlevel " << fromlevel;
                // cerr<< " tolevel " << tolevel << " salt " << salt << " key
                // "; myPrint(key, AES_KEY_BYTES);
            }
            //cerr << "++> crypting " << data << " with key "; myPrint(key,
            // AES_KEY_BYTES); cerr << "\n";

        }
    }

    string resu = cm->crypt(
        cm->getmkey(), data, ft, anonfullname, fromlevel, tolevel, salt);
    if (VERBOSE_V) {
        //cerr << "result is " << resu << "\n";
    }
    return resu;
}
