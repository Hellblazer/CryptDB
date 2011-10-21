#include <iostream>
#include <fstream>
#include <set>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <util/ctr.hh>
#include <util/cryptdb_log.hh>
#include <util/cleanup.hh>

#include <edb/EDBProxy.hh>

using namespace std;

#if MYSQL_S

#define DECRYPT_int_sem "decrypt_int_sem"
#define DECRYPT_int_det "decrypt_int_det"
#define ENCRYPT_int_det "encrypt_int_det"
#define DECRYPT_text_sem "decrypt_text_sem"
#define DECRYPT_text_det "decrypt_text_det"
#define SEARCH "search"
#define SEARCHSWP "searchSWP"
#define FUNC_ADD_FINAL "agg"
#define SUM_AGG "agg"
#define FUNC_ADD_SET "func_add_set"

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

static bool VERBOSE_V = VERBOSE_EDBProxy_VERY;

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
                    "DROP FUNCTION IF EXISTS " SEARCHSWP "; "),
                "cannot drop " SEARCHSWP);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " FUNC_ADD_FINAL "; "),
             "cannot drop " FUNC_ADD_FINAL);
    myassert(conn->execute(
                 "DROP FUNCTION IF EXISTS " FUNC_ADD_SET "; "),
             "cannot drop " FUNC_ADD_SET);

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
createAll(Connect * conn)
{
    myassert(conn->execute(
                 "CREATE FUNCTION "DECRYPT_int_sem" RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf decrypt_int_sem ");
    myassert(conn->execute(
                 "CREATE FUNCTION "DECRYPT_int_det" RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf decrypt_int_det");
    myassert(conn->execute(
                 "CREATE FUNCTION "ENCRYPT_int_det" RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf encrypt_int_det");
    myassert(conn->execute(
                 "CREATE FUNCTION "DECRYPT_text_sem" RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf decrypt_text_sem");
    myassert(conn->execute(
                 "CREATE FUNCTION "DECRYPT_text_det" RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf decrypt_text_det");
    myassert(conn->execute(
                 "CREATE FUNCTION "SEARCH" RETURNS INTEGER SONAME 'edb.so'; "),
             "failed to create udf search");
    myassert(conn->execute(
                 "CREATE AGGREGATE FUNCTION agg RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf agg");
    myassert(conn->execute(
                 "CREATE FUNCTION func_add_set RETURNS STRING SONAME 'edb.so'; "),
             "failed to create udf func_add_set");
    myassert(conn->execute(
                 "CREATE FUNCTION "SEARCHSWP" RETURNS INTEGER SONAME 'edb.so'; "),
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

#if NOTDEMO
static void sCreateMetaSchema( Connect& pconn ) {

    DBResult* reply;

    // Create persistent representation for TabledMetadata in edb/util.h
    //    pconn.execute( "CREATE TABLE table_info"
                   "( id bigint NOT NULL auto_increment PRIMARY KEY"
                   ", name varchar(64) NOT NULL"
                   ", anon_name varchar(64) NOT NULL"
                   ", salt_name varchar(4096) NOT NULL"
                   ", auto_inc_field varchar(64)"
                   ", auto_inc_value bigint"
                   ", UNIQUE INDEX idx_table_name( name )"
                   ");"
                   , reply );

    // Create persistent representation for FieldMetadata in edb/util.h
    //
    pconn.execute( "CREATE TABLE column_info"
                   "( id bigint NOT NULL auto_increment PRIMARY KEY"
                   ", table_id bigint NOT NULL"
                   ", field_type int NOT NULL"
                   ", mysql_field_type int NOT NULL"
                   ", name varchar(64) NOT NULL"
                   ", anon_det_name varchar(64)"
                   ", anon_ope_name varchar(64)"
                   ", anon_agg_name varchar(64)"
                   ", anon_swp_name varchar(64)"
                   ", salt_name varchar(4096)"
                   ", is_encrypted tinyint NOT NULL"
                   ", can_be_null tinyint NOT NULL"
                   ", has_ope tinyint NOT NULL"
                   ", has_agg tinyint NOT NULL"
                   ", has_search tinyint NOT NULL"
                   ", has_salt tinyint NOT NULL"
                   ", ope_used tinyint NOT NULL"
                   ", agg_used tinyint NOT NULL"
                   ", search_used tinyint NOT NULL"
                   ", update_set_performed tinyint NOT NULL"
                   ", sec_level_ope enum"
                   "      ( 'INVALID'"
                   "      , 'PLAIN'"
                   "      , 'PLAIN_DET'"
                   "      , 'DETJOIN'"
                   "      , 'DET'"
                   "      , 'SEMANTIC_DET'"
                   "      , 'PLAIN_OPE'"
                   "      , 'OPEJOIN'"
                   "      , 'OPE'"
                   "      , 'SEMANTIC_OPE'"
                   "      , 'PLAIN_AGG'"
                   "      , 'SEMANTIC_AGG'"
                   "      , 'PLAIN_SWP'"
                   "      , 'SWP'"
                   "      , 'SEMANTIC_VAL'"
                   "      , 'SECLEVEL_LAST'"
                   "      ) NOT NULL DEFAULT 'INVALID'"
                   ", sec_level_det enum"
                   "      ( 'INVALID'"
                   "      , 'PLAIN'"
                   "      , 'PLAIN_DET'"
                   "      , 'DETJOIN'"
                   "      , 'DET'"
                   "      , 'SEMANTIC_DET'"
                   "      , 'PLAIN_OPE'"
                   "      , 'OPEJOIN'"
                   "      , 'OPE'"
                   "      , 'SEMANTIC_OPE'"
                   "      , 'PLAIN_AGG'"
                   "      , 'SEMANTIC_AGG'"
                   "      , 'PLAIN_SWP'"
                   "      , 'SWP'"
                   "      , 'SEMANTIC_VAL'"
                   "      , 'SECLEVEL_LAST'"
                   "      ) NOT NULL DEFAULT 'INVALID'"
                   ", INDEX idx_column_name( name )"
                   ", FOREIGN KEY( table_id ) REFERENCES table_info( id ) ON DELETE CASCADE"
                   ");"
                   , reply );

    // Create persistent representation for IndexMetadata in edb/util.h
    //
    pconn.execute( "CREATE TABLE index_info"
                   "( id bigint NOT NULL auto_increment PRIMARY KEY"
                   ", table_id bigint NOT NULL"
                   ", name varchar(64) NOT NULL"
                   ", anon_name varchar(64) NOT NULL"
                   ", FOREIGN KEY( table_id ) REFERENCES table_info( id ) ON DELETE CASCADE"
                   ");"
                   , reply );
}

void EDBProxy::readMetaInfo( ) {
    DBResult* reply;
    Connect pconn( meta_db.conn() );

    pconn.execute( "SHOW DATABASES", reply );
    ResType show_type = reply->unpack();
    bool found_dbname = false;
    for (auto db_it = show_type.rows.begin(); db_it != show_type.rows.end(); ++db_it) {
        auto db_info = *db_it;
        auto field_it = db_info.begin();
        if ((*field_it).to_string() == "proxy_db") {
            found_dbname = true;
        }
    }

    if (!found_dbname) {
        if (pconn.execute( "CREATE DATABASE proxy_db", reply))
            sCreateMetaSchema( pconn );
    }

    pconn.execute( "USE proxy_db", reply );

    pconn.execute( "SHOW TABLES", reply );
    if (reply->n->row_count < 3) {
        sCreateMetaSchema( pconn );
    }

    pconn.execute( "SELECT id, name, anon_name, salt_name, auto_inc_field, auto_inc_value FROM table_info", reply );

    ResType res_type = reply->unpack();

    for (auto table_it = res_type.rows.begin(); table_it != res_type.rows.end(); ++table_it) {
        TableMetadata* tm = new TableMetadata();
        auto table_info = *table_it;

        auto field_it = table_info.begin();

        tm->tableNo       = atoi((*field_it++).to_string().c_str());
        string table_name =      (*field_it++).to_string();
        tm->anonTableName =      (*field_it++).to_string();
        tm->salt_name     =      (*field_it++).to_string();
        tm->ai.field      =      (*field_it++).to_string();
        tm->ai.incvalue   = atoi((*field_it++).to_string().c_str());
        tm->hasEncrypted  = false;
        tm->hasSensitive  = false;

        tableMetaMap[table_name] = tm;

        this->totalTables = tm->tableNo;
    }

    map<string,SECLEVEL> seclevel_map = {
        {"INVALID", SECLEVEL::INVALID}, 
        {"PLAIN", SECLEVEL::PLAIN}, 
        {"PLAIN_DET", SECLEVEL::PLAIN_DET},
        {"DETJOIN", SECLEVEL::DETJOIN}, 
        {"DET", SECLEVEL::DET}, 
        {"SEMANTIC_DET", SECLEVEL::SEMANTIC_DET}, 
        {"PLAIN_OPE", SECLEVEL::PLAIN_OPE}, 
        {"OPEJOIN", SECLEVEL::OPEJOIN}, 
        {"OPE", SECLEVEL::OPE}, 
        {"SEMANTIC_OPE", SECLEVEL::SEMANTIC_OPE}, 
        {"PLAIN_AGG", SECLEVEL::PLAIN_AGG}, 
        {"SEMANTIC_AGG", SECLEVEL::SEMANTIC_AGG}, 
        {"PLAIN_SWP", SECLEVEL::PLAIN_SWP}, 
        {"SWP", SECLEVEL::SWP}, 
        {"SEMANTIC_VAL", SECLEVEL::SEMANTIC_VAL}, 
        {"SECLEVEL_LAST", SECLEVEL::SECLEVEL_LAST}
    };

    for (auto tm_it = tableMetaMap.begin(); tm_it != tableMetaMap.end(); ++tm_it) {
        TableMetadata* tm = tm_it->second;

        char buf[16];
        snprintf( buf, 15, "%d", tm->tableNo );
        string table_id( buf );

        pconn.execute( "SELECT field_type, mysql_field_type, name, anon_det_name, anon_ope_name, anon_agg_name, anon_swp_name,"
                       "       salt_name, is_encrypted, can_be_null, has_ope, has_agg, has_search, has_salt,"
                       "       ope_used, agg_used, search_used, update_set_performed, sec_level_ope, sec_level_det "
                       "FROM column_info "
                       "WHERE table_id=" + table_id, reply ); 

        res_type = reply->unpack();

        SqlItem si;
        for (auto column_it = res_type.rows.begin(); column_it != res_type.rows.end(); ++column_it) {
            FieldMetadata* fm = new FieldMetadata();
            auto column_info = *column_it;

            auto field_it = column_info.begin();

            fm->type                 = (fieldType)atoi( (*field_it++).to_string().c_str() );
            fm->mysql_type           = (enum_field_types)atoi( (*field_it++).to_string().c_str() );

            string col_name          = (*field_it++).to_string();
            fm->anonFieldNameDET     = (*field_it++).to_string();
            fm->anonFieldNameOPE     = (*field_it++).to_string();
            fm->anonFieldNameAGG     = (*field_it++).to_string();
            fm->anonFieldNameSWP     = (*field_it++).to_string();
            fm->salt_name            = (*field_it++).to_string();
            fm->isEncrypted          = (*field_it++).to_string().compare( "1" ) == 0;
            fm->can_be_null          = (*field_it++).to_string().compare( "1" ) == 0;
            fm->has_ope              = (*field_it++).to_string().compare( "1" ) == 0;
            fm->has_agg              = (*field_it++).to_string().compare( "1" ) == 0;
            fm->has_search           = (*field_it++).to_string().compare( "1" ) == 0;
            fm->has_salt             = (*field_it++).to_string().compare( "1" ) == 0;
            fm->ope_used             = (*field_it++).to_string().compare( "1" ) == 0;
            fm->agg_used             = (*field_it++).to_string().compare( "1" ) == 0;
            fm->search_used          = (*field_it++).to_string().compare( "1" ) == 0;
            fm->update_set_performed = (*field_it++).to_string().compare( "1" ) == 0;

            fm->secLevelOPE          = seclevel_map[(*field_it++).to_string()];
            fm->secLevelDET          = seclevel_map[(*field_it++).to_string()];

            tm->fieldNameMap[fm->anonFieldNameDET] = col_name;
            tm->fieldNameMap[fm->anonFieldNameOPE] = col_name;
            tm->fieldNameMap[fm->anonFieldNameAGG] = col_name;
            tm->fieldNameMap[fm->anonFieldNameSWP] = col_name;
            tm->fieldMetaMap[col_name] = fm;

            if (col_name.compare( tm->salt_name ))
                // don't add the fmsalt field to fieldNames
                // the insert pathway counts on it NOT being there
                tm->fieldNames.push_back( col_name );


            if (fm->isEncrypted) tm->hasEncrypted = true;
            // FIXME!  what to do about tm->hasSensitive / multi-princ?
        }
    }
}

static string sGetProxyDirectory( const string& proxy_directory, const string& dbname) {

    string result = proxy_directory;
    if (result.length() == 0) {
        // use user's home directory as 
        result += getpwuid(getuid())->pw_dir;
        result += "/" + dbname;
    } else {
        result += "/" + dbname;
    }

    string message = "embedded_db in: ";

    struct stat st;
    if (stat(result.c_str(), &st) != 0) {
        string mkdir_cmd = "mkdir -p " + result;
        if (system( mkdir_cmd.c_str() ) == -1)
            message = "failed to mkdir -p ";
    }

    cerr << message << result << endl;

    return result;
}
#endif

//============== Constructors ==================================//

EDBProxy::EDBProxy(const string& server
                   , const string& user
                   , const string& psswd
                   , const string& dbname
                   , uint port
                   , bool multiPrinc
                   , bool defaultEnc
                   , const string& proxy_directory)
    : VERBOSE( VERBOSE_EDBProxy )
    , dropOnExit( false )
    , isSecure( false )
    , allDefaultEncrypted( defaultEnc )
#if NOTDEMO
    , meta_db( sGetProxyDirectory(proxy_directory, dbname) )
#endif
    , conn( new Connect(server, user, psswd, dbname, port) )
    , pm( nullptr )
    , mp( multiPrinc ? new MultiPrinc(conn) : nullptr )
    , totalTables( 0 )
    , totalIndexes( 0 )
    , overwrite_creates( false )

{
    dropAll(conn);
    createAll(conn);
    LOG(edb_v) << "UDFs loaded successfully";
    LOG(edb_v) << (multiPrinc ? "multi princ mode" : "single princ mode");

    assert_s (!(multiPrinc && defaultEnc), "cannot have fields encrypted by default in multiprinc because we need to know encfor princ");

#if NOTDEMO
    this->readMetaInfo( );
#endif
}


void
EDBProxy::setMasterKey(const string &mkey)
{
    isSecure = true;
    cm = new CryptoManager(mkey);
}

ResType
EDBProxy::plain_execute(const string &query)
{
    LOG(edb) << "in plain execute";
    DBResult * reply;
    if (!conn->execute(query, reply)) {
        LOG(edb) << "failed to execute: " << query;
        return ResType(false);
    }

    ResType r = reply->unpack();
    delete reply;
    return r;
}

//ENCRYPTION TABLES
/*
//will create encryption tables and will use them
//noOPE encryptions and noHOM encryptions
void
EDBProxy::createEncryptionTables(int noOPE, int noHOM)
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
EDBProxy::replenishEncryptionTables()
{
    cm->replenishEncryptionTables();
}
*/
// it must point to first word of type
// advances it after the last part of type
// returns the type string from the query
// sets the type of the field in fm to either integer or string
static string
setType(list<string>::iterator & it, list<string> & words, FieldMetadata * fm)
{

    string token = *it;
    bool isint = false;
    if (it->find("int") != string::npos) {
        isint = true;
    }
    if (it->find("decimal") != string::npos) {
        isint = true;
    }

    if (isint) {
        fm->type = TYPE_INTEGER;
        fm->mysql_type = MYSQL_TYPE_LONG;
    } else {
        fm->type = TYPE_TEXT;
        fm->mysql_type = MYSQL_TYPE_STRING;
    }

    string res = *it;
    it++;
    res += processParen(it, words);

    return res;
}

list<string>
EDBProxy::processIndex(list<string> & words,
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
    im->anonIndexName = string("index") + strFromVal(totalIndexes);
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
    if (mp) {
        return (toLowerCase(token).compare("encfor") == 0);
    } else {
        return (toLowerCase(token).compare("enc") == 0);
    }
   }
 */

static string
getAnonNameForFilter(FieldMetadata * fm, onion o)
{
    if (!fm->isEncrypted) {
        return fm->fieldName;
    }
    if (o == oDET) {
        //for equality type operations use OPE if you can
      /*  if (fm->has_ope &&
            (fm->secLevelOPE != SECLEVEL::SEMANTIC_OPE)) {
            return fm->anonFieldNameOPE;
        } else {
            return fm->anonFieldNameDET;
        }*/
        return fm->anonFieldNameDET;
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
                  FieldMetadata * fm, map<string, TableMetadata *> & tm, bool defaultEnc)
{
    if (DECRYPTFIRST) {
        tm[tableName]->fieldMetaMap[fieldName]->secLevelDET = SECLEVEL::DETJOIN;
        //make ope onion uncovered to avoid adjustment --- though this onion
        // does not exist in this mode
        tm[tableName]->fieldMetaMap[fieldName]->secLevelOPE = SECLEVEL::OPE;
        return;
    }

    fm->isEncrypted = defaultEnc;
    while (annotations.find(*wordsIt) != annotations.end()) {
        string annot = toLowerCase(*wordsIt);

        if (annot == "enc") {
            fm->isEncrypted = true;

            wordsIt++;
            continue;
        }

        if (annot == "search") {
            fm->has_search = true;
            wordsIt++;
            continue;
        }
        // MULTI-PRINC annotations
        if (mp) {
            if (annot == "encfor") {
                fm->isEncrypted = true;
            }
            //cerr << "before mp-process an \n";
            mp->processAnnotation(wordsIt, words, tableName, fieldName,
                    fm->isEncrypted,
                    tm);
        }
    }

}

// records if a field has auto_increment or it if it has non null
static void
processPostAnnotations(TableMetadata * tm, FieldMetadata * fm, string field, list<string>::iterator wordsIt, const list<string> & words) {

    string res = "";
    /* This function is implemented ad-hoc.. the generic parser will fix this. */
    while ((wordsIt != words.end()) && (*wordsIt != ")") && (*wordsIt != ",")) {
        //cerr << "post annotate: " << *wordsIt << endl;
        if (equalsIgnoreCase(*wordsIt, "(")) {
            processParen(wordsIt, words);
            continue;
        }
        if (equalsIgnoreCase(*wordsIt, "not")) {
            list<string>::iterator nextIt = wordsIt;
            nextIt++;
            if (nextIt!=words.end()) {
                if (equalsIgnoreCase(*nextIt,"null")) {
                    fm->can_be_null = false;
                    wordsIt = nextIt;
                }
            }
            wordsIt++;
            continue;
        }
        if (equalsIgnoreCase(*wordsIt, "auto_increment")) {
            assert_s(tm->ai.field == "", " table cannot have two autoincrements");
            tm->ai.field = field;
            LOG(edb) << "auto_increment field " << field;
            wordsIt++;
            continue;
        }
        if (fm->isEncrypted) {
            assert_s(!equalsIgnoreCase(*wordsIt, "key"), "do not support key specification in encrypted field properties currently; specify it at end of table");
        }
        wordsIt++;
    }
    //cerr << "arg2 " << *wordsIt << endl;
    return;

}

list<string>
EDBProxy::rewriteEncryptCreate(const string &query)
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

    bool already_exists = false;

    if (!overwrite_creates) {
        assert_s(tableMetaMap.find(
                tableName) == tableMetaMap.end(),"table already exists: " +
                tableName );
    } else {
        if (tableMetaMap.find(tableName) != tableMetaMap.end()) {
            already_exists = true;
        }
    }

    unsigned int tableNo = totalTables;
    totalTables++;
    //create anon name
    string anonTableName = anonymizeTableName(tableNo, tableName, !!mp);

    tableNameMap[anonTableName] = tableName;

    //create new table structure
    TableMetadata * tm;

    if (already_exists) {
        tm = tableMetaMap[tableName];
    } else {
        tm = new TableMetadata();
        tableMetaMap[tableName] = tm;
        tm->fieldNameMap = map<string, string>();
        tm->fieldNames = list<string>();
        tm->tableNo = tableNo;
        tm->anonTableName = anonTableName;
        tm->fieldMetaMap = map<string, FieldMetadata *>();
        tm->hasEncrypted = false;
        tm->hasSensitive = false;
    }

    //populate table structure
    //fill the fieldNameMap and fieldMetaMap and prepare the anonymized query

    string resultQuery = "CREATE TABLE ";

    roll<string>(wordsIt, 2);
    unsigned int i = 0;

    std::set<string> terms = { ",", ")" };

    string fieldSeq = "";

    while (wordsIt != words.end()) {
        string fieldName = *wordsIt;

        //primary key, index, other metadata about data layout
        if (contains(fieldName, createMetaKeywords)) {
            //if (VERBOSE) { cerr << fieldName << " is meta \n"; }
            //mirrorUntilTerm should stop at the comma
            fieldSeq +=  mirrorUntilTerm(wordsIt, words, {","}, 1, 1);
            continue;
        }

        if (!already_exists) {
            assert_s(tm->fieldMetaMap.find(
                    fieldName) == tm->fieldMetaMap.end(),
                    "field %s already exists in table " +  fieldName + " " +
                    tableName);

            tm->fieldNames.push_back(fieldName);
        }

        FieldMetadata * fm;

        if (already_exists) {
            fm = tm->fieldMetaMap[fieldName];
        } else {
            fm = new FieldMetadata();
            tm->fieldMetaMap[fieldName] =  fm;
            fm->fieldName = fieldName;
        }

        wordsIt++;

        LOG(edb_v) << "fieldname " << fieldName;

        //decides if this field is encrypted or not
        //also decides which onions to create
        processAnnotation(mp, wordsIt, words, tableName, fieldName,
                          fm,
                          tableMetaMap, allDefaultEncrypted);


        if (fm->isEncrypted) {
            LOG(edb_v) << "encrypted field";
            tm->hasEncrypted = true;
            tm->hasSensitive = true;
        } else {
            LOG(edb_v) << "not enc " << fieldName;
            //record auto increments:
            processPostAnnotations(tm, fm, fieldName, wordsIt, words);
            //cerr << "arg " << *wordsIt << endl;
            fieldSeq = fieldSeq + fieldName + " " + mirrorUntilTerm(wordsIt, words, {","}, 1, 1);
            continue;
        }

        //ONLY ENCRYPTED FIELDS

        setType(wordsIt, words,  fm);
        //now wordsIt points to first word after type

        fieldSeq += processCreate(fm->type, fieldName, i, tm,
                                  fm, !!mp) + " ";

        //record not nulls
        processPostAnnotations(tm, fm, fieldName, wordsIt, words);

        //do not add field properties, only add "," or ")"
        mirrorUntilTerm(wordsIt, words, terms, 0);
        fieldSeq += mirrorUntilTerm(wordsIt, words, terms, 1);

        i++;
    }

    if (!tm->hasEncrypted) {
        tm->anonTableName = tableName;
    }
    resultQuery = resultQuery + tm->anonTableName + " ( ";

    if (tm->hasEncrypted) {
        tm->salt_name = getTableSalt(tm->anonTableName);
        resultQuery += " " + tm->salt_name + " " + TN_SALT + ", ";
        FieldMetadata * fmsalt = new FieldMetadata();
        fmsalt->type = TYPE_INTEGER;
        fmsalt->fieldName = tm->salt_name;
        tm->fieldMetaMap[fmsalt->fieldName] = fmsalt;
    }


    /* begin update persistent meta information in proxy_db */
#if NOTDEMO
    Connect pconn( meta_db.conn() );

    pconn.execute( "BEGIN;" );

    string insert_into( "INSERT INTO" );

    pconn.execute( insert_into + " table_info VALUES "
                   + "( " + "0"               // the auto-incremented ID for this record
                   + ", '" + tableName + "'"
                   + ", '" + tm->anonTableName + "'"
                   + ", '" + tm->salt_name + "'"
                   + ", '" + tm->ai.field + "'"
                   + ", " + "0"               // the auto_inc_value for the TableMetadata
                   + ");" );

    char table_id[16];
    sprintf( table_id, "%lld", pconn.last_insert_id() );
    

    for (map<string, FieldMetadata*>::iterator it = tm->fieldMetaMap.begin(); it != tm->fieldMetaMap.end(); ++it) {
        string col_name   = it->first;
        FieldMetadata* fm = it->second;

        char ftype[16];
        char mtype[16];

        snprintf( ftype, 15, "%d", fm->type );
        snprintf( mtype, 15, "%d", fm->mysql_type );

        pconn.execute( insert_into + " column_info VALUES "
                       + "( " + "0"               // the auto-incremented ID for this record
                       + ", " + table_id
                       + ", " + ftype
                       + ", " + mtype
                       + ", " + "'" + col_name + "'"
                       + ", " + (fm->anonFieldNameDET.empty() ? "null" : "'" + fm->anonFieldNameDET + "'" )
                       + ", " + (fm->anonFieldNameOPE.empty() ? "null" : "'" + fm->anonFieldNameOPE + "'" )
                       + ", " + (fm->anonFieldNameAGG.empty() ? "null" : "'" + fm->anonFieldNameAGG + "'" )
                       + ", " + (fm->anonFieldNameSWP.empty() ? "null" : "'" + fm->anonFieldNameSWP + "'" )
                       + ", " + (fm->salt_name.empty()        ? "null" : "'" + fm->salt_name + "'" )
                       + ", " + (fm->isEncrypted ? "1" : "0")
                       + ", " + (fm->can_be_null ? "1" : "0")
                       + ", " + (fm->has_ope     ? "1" : "0")
                       + ", " + (fm->has_agg     ? "1" : "0")
                       + ", " + (fm->has_search  ? "1" : "0")
                       + ", " + (fm->has_salt    ? "1" : "0")
                       + ", " + (fm->ope_used    ? "1" : "0")
                       + ", " + (fm->agg_used    ? "1" : "0")
                       + ", " + (fm->search_used ? "1" : "0")
                       + ", " + (fm->update_set_performed ? "1" : "0")
                       + ", " + "'" + levelnames[(int)fm->secLevelOPE] + "'"
                       + ", " + "'" + levelnames[(int)fm->secLevelDET] + "'"
                       + ");" );
    }

    pconn.execute( "COMMIT;" );
#endif
    /* end update persistent meta information in proxy_db */

    resultQuery += fieldSeq;

    //mirror query until the end, it may have formatting commands
    resultQuery = resultQuery + mirrorUntilTerm(wordsIt, words, {});
    resultQuery = resultQuery + ";";

    return list<string>(1, resultQuery);
}

//TODO: MULTIPRINC does not have update fully implemented
list<string>
EDBProxy::rewriteEncryptUpdate(const string &query)
throw (CryptDBError)
{

    //    UPDATE folders SET mitgeec = 'DOC', mitgeecs_app_term = '9/2007' WHERE
    // id = '99e89298fa'

    FieldsToDecrypt fieldsDec;

    list<string> words = getSQLWords(query);
    QueryMeta qm = getQueryMeta(cmd::UPDATE, words, tableMetaMap);
    auto ANON = cleanup([&qm]() { qm.cleanup(); });

    TMKM tmkm;
    if (mp) {
        tmkm.processingQuery = true;
        mp->getEncForFromFilter(cmd::UPDATE, words, tmkm, qm, tableMetaMap);
    }

    list<string>::iterator wordsIt = words.begin();

    //skip over UPDATE
    string resultQuery = "UPDATE ";
    wordsIt++;

    //table
    assert_s(tableMetaMap.find(
                 *wordsIt) != tableMetaMap.end(),
             " table to update does not exist" );

    string table = *wordsIt;
    TableMetadata * tm  = tableMetaMap[table];

    resultQuery = resultQuery + tm->anonTableName;
    wordsIt++;

    //skip over SET
    resultQuery = resultQuery + " SET ";
    wordsIt++;

    while ((wordsIt != words.end()) &&
           (!equalsIgnoreCase(*wordsIt,"where"))) {

        string field = * wordsIt;

        wordsIt++;

        std::set<string> term = {",", "where"};
        FieldMetadata * fm = tm->fieldMetaMap[field];

        if (!fm->isEncrypted) {
            resultQuery = resultQuery + " " + field +  mirrorUntilTerm(
                wordsIt, words, term, 0, 1);
            if (wordsIt == words.end()) {
                continue;
            }
            if (wordsIt->compare(",") == 0) {
                resultQuery += ", ";
                wordsIt++;
            }
            continue;
        }

        //FIELD IS ENCRYPTED


        string anonTableName = tm->anonTableName;
        wordsIt++;
        fieldType ft = fm->type;

        //detect if it is an increment
        if (isField(*wordsIt)) {         //this is an increment

            if (VERBOSE) { LOG(edb_v) << "increment for " << field; }

            assert_s(wordsIt->compare(field) == 0, "must increment its own value not some other field");

            fm->INCREMENT_HAPPENED = true;
            fm->agg_used = true;

            string anonFieldName = getOnionName(fm, oAGG);

            wordsIt++;

            assert_s(wordsIt->compare("+") == 0, "can only update with plus");
            string op = *wordsIt;
            wordsIt++;             // points to value now



            if (DECRYPTFIRST) {
                resultQuery += field + " =  encrypt_int_det( "+
                        fieldNameForQuery(
                                tableMetaMap[table]->anonTableName,
                                table, field,
                                fm, qm) +  " + " +
                                *wordsIt + ", "+
                                CryptoManager::marshallKey(
                                        dec_first_key) + ") ";
            } else {
                resultQuery += anonFieldName + " =  func_add_set (" +
                        anonFieldName +  ", "
                        + dataForQuery(*wordsIt, ft,
                                fullName(field,
                                        table),
                                        fullName(anonFieldName,
                                                anonTableName),
                                                SECLEVEL::PLAIN_AGG, SECLEVEL::SEMANTIC_AGG, 0,
                                                tmkm) + ", "
                                                + marshallBinary(cm->getPKInfo()) + ") ";
            }


            wordsIt++;

            resultQuery += checkStr(wordsIt, words, ",", "");
            continue;
        }

        //encryption fields that are not increment
        fm->update_set_performed = true;

        uint64_t salt = 0;
        if (fm->has_salt) {
            salt = randomValue();
        } else {
            //this field must be at DET and OPE or lower
            assert_s((fm->secLevelDET != SECLEVEL::SEMANTIC_DET) && (fm->secLevelOPE != SECLEVEL::SEMANTIC_OPE), "this field cannot have a semantic level yet not have a salt");
        }

        if (ft == TYPE_INTEGER) {
            string val = *wordsIt;

            //pass over value
            wordsIt++;

            string anonfieldName = getOnionName(fm, oDET);
            resultQuery = resultQuery + anonfieldName  + " = ";

            if (DECRYPTFIRST) {
                resultQuery += processValsToInsert(field, fm, table, tm, salt, val, tmkm);
            } else {

                resultQuery = resultQuery +
                        dataForQuery(val, TYPE_INTEGER,
                                fullName(field,
                                        table),
                                        fullName(anonfieldName,
                                                anonTableName),
                                                SECLEVEL::PLAIN_DET, fm->secLevelDET, salt, tmkm);

                if (fm->has_ope) {
                    anonfieldName = fm->anonFieldNameOPE;
                    resultQuery = resultQuery  + ", " + anonfieldName + " = ";

                    resultQuery = resultQuery +
                                  dataForQuery(val, TYPE_INTEGER,
                                        fullName(field,
                                                 table),
                                        fullName(anonfieldName,
                                                 anonTableName),
                                        SECLEVEL::PLAIN_OPE, fm->secLevelOPE, salt, tmkm);

                }
                if (fm->has_agg) {
                    anonfieldName = fm->anonFieldNameAGG;
                    resultQuery = resultQuery  + ", " + anonfieldName +
                                  " = " +
                                  dataForQuery(val, TYPE_INTEGER,
                                        fullName(field,
                                                 table),
                                        fullName(anonfieldName,
                                                 anonTableName),
                                        SECLEVEL::PLAIN_AGG, SECLEVEL::SEMANTIC_AGG, salt, tmkm);
                }

            }
        }
        if (ft == TYPE_TEXT) {

            string val = *wordsIt;
            //pass over value
            wordsIt++;

            assert_s(hasApostrophe(
                    val), "missing apostrophe for type text");

            if (DECRYPTFIRST) {
                resultQuery = resultQuery + " "  + field + " = " +
                        processValsToInsert(field, fm, table, tm, 0, val,
                                tmkm);
            } else {

                //DET onion

                //encrypt the value
                string anonfieldname = getOnionName(fm, oDET);

                resultQuery = resultQuery + " "  + anonfieldname +
                        " = " +
                        dataForQuery(val, TYPE_TEXT,
                                fullName(field,
                                        table),
                                        fullName(anonfieldname,
                                                anonTableName),
                                                SECLEVEL::PLAIN_DET, fm->secLevelDET, salt, tmkm);

                //OPE onion
                if (fm->has_ope) {
                    string anonName = fm->anonFieldNameOPE;

                    resultQuery += ", " + anonName + " = " +
                            dataForQuery(val, TYPE_TEXT,
                                    fullName(field,table),
                                    fullName(anonName,
                                            anonTableName),
                                            SECLEVEL::PLAIN_OPE, fm->secLevelOPE, salt,
                                            tmkm);
                }

                //OPE onion
                if (fm->has_search) {
                    string anonName = fm->anonFieldNameSWP;

                    resultQuery += ", " + anonName + " = " +
                            dataForQuery(val, TYPE_TEXT,
                                    fullName(field,table),
                                    fullName(anonName, anonTableName),
                                    SECLEVEL::PLAIN_SWP, SECLEVEL::SWP, salt, tmkm);
                }
            }

        }

        if (fm->has_salt) {
            resultQuery += ", " + fm->salt_name + " = " + StringFromVal(salt);
        }

        resultQuery += checkStr(wordsIt, words, ",", "");
    }

    list<string>  res =
        processFilters(wordsIt, words, qm,  resultQuery, fieldsDec,
                       tmkm);

    LOG(edb) << " no. of translated queries " << res.size() << "\n";
    LOG(edb) << "Translated query: " << res.front() << "\n";
    return res;
}

list<string>
EDBProxy::processFilters(list<string>::iterator &  wordsIt,
                          list<string> & words, QueryMeta & qm,
                          string resultQuery,
                          FieldsToDecrypt fieldsDec, TMKM & tmkm,
                          list<string> subqueries)
throw (CryptDBError)
{
    std::set<string> keys = {"AND", "OR", "NOT", "(", ")"};

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
        if (contains(*wordsIt, keys)) {
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

                if (fm->secLevelOPE == SECLEVEL::SEMANTIC_OPE) {
                    addIfNotContained(fullName(field,
                                               table), fieldsDec.OPEFields);
                }

            } else {                    //group
                if (fm->secLevelDET == SECLEVEL::SEMANTIC_DET) {
                    addIfNotContained(fullName(field,
                                               table), fieldsDec.DETFields);
                }
            }

            if (comm.compare("group") == 0) {
                anonField = getAnonNameForFilter(fm, oDET);
            } else {
                //order by
                anonField = getAnonNameForFilter(fm, oOPE);

            }

            resultQuery = resultQuery + " " +
                          fieldNameForQuery(
                tableMetaMap[table]->anonTableName, table,
                anonField, fm, qm);

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

    if ((wordsIt != words.end() && (equalsIgnoreCase(*wordsIt, "for")))) {
          resultQuery = resultQuery + " for ";
          wordsIt++;
          assert_s(equalsIgnoreCase(*wordsIt, "update"), "expected that 'for' be followed by 'update'");
          resultQuery = resultQuery + *wordsIt + " ";
          wordsIt++;
      }

    if ((wordsIt != words.end() && (equalsIgnoreCase(*wordsIt, "limit")))) {
        resultQuery = resultQuery + " limit ";
        wordsIt++;
        resultQuery = resultQuery + *wordsIt + " ";
        wordsIt++;
    }

    resultQuery = resultQuery + ";";

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
EDBProxy::processDecryptions(FieldsToDecrypt fieldsDec, TMKM & tmkm)
throw (CryptDBError)
{
    list<string> result;

    QueryMeta qm;

    for (list<string>::iterator it = fieldsDec.DETFields.begin();
         it != fieldsDec.DETFields.end(); it++) {
        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];

        if (!fm->isEncrypted) {
            continue;
        }

        if (mp) {
            assert_s(false,
                     "there should be no adjustment in multi-key mode\n");
        }

        string whereClause = ";";
        string fname = fullName(field, table);

        /*if (mp) {
                assert_s((mkm.encForMap.find(fname) != mkm.encForMap.end()) &&
                   (tmkm.encForVal.find(fname) != tmkm.encForVal.end()),
                   "internal: process decryptions missing data for encrypted
                   field");
                whereClause = " WHERE " + getField(mkm.encForMap[fname]) + " =
                   " + tmkm.encForVal[mkm.encForMap[fname]] + whereClause;
           }*/

        string anonTableName = tm->anonTableName;
        string anonfieldName = getOnionName(fm, oDET);

        fieldType ft = fm->type;

        string decryptS;
        //first prepare the decryption call string

        string salt_name;
        if (fm->has_salt) {
            salt_name = fm->salt_name;
        } else {
            salt_name = tm->salt_name;
        }

        switch (ft) {
        case TYPE_INTEGER: {
            decryptS = "decrypt_int_sem(" + anonfieldName + "," +
                       cm->marshallKey(cm->getKey(fullName(anonfieldName,
                                                           anonTableName),
                                                  SECLEVEL::SEMANTIC_DET)) + ", " + salt_name
                       + ")" + whereClause;
            //cout << "KEY USED TO DECRYPT field from SEM " << anonfieldName
            // << " " << cm->marshallKey(cm->getKey(anonTableName
            // +"."+anonfieldName, SECLEVEL::SEMANTIC)) << "\n"; fflush(stdout);
            break;
        }
        case TYPE_TEXT: {
            decryptS = "decrypt_text_sem(" + anonfieldName + "," +
                       cm->marshallKey(cm->getKey(fullName(anonfieldName,
                                                           anonTableName),
                                                  SECLEVEL::SEMANTIC_DET)) + ", " +
                        salt_name + ")" + whereClause;
            break;
        }

        default: {assert_s(false, "invalid type"); }

        }

        string resultQ = string("UPDATE ") +
                         tableMetaMap[table]->anonTableName +
                         " SET " + anonfieldName + "= " + decryptS;

        result.push_back(resultQ);

        fm->secLevelDET = SECLEVEL::DET;
    }

    for (list<string>::iterator it = fieldsDec.OPEFields.begin();
         it != fieldsDec.OPEFields.end(); it++) {
        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];

        if (!fm->isEncrypted) {
            continue;
        }

        if (mp) {
            assert_s(false,
                     "there should be no adjustment in multi-key mode\n");
        }
        string whereClause = ";";
        string fname = fullName(field, table);

        string salt_name;
        if (fm->has_salt) {
            salt_name = fm->salt_name;
        } else {
            salt_name = tm->salt_name;
        }

        /*if (mp) {
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
                                                     SECLEVEL::SEMANTIC_OPE)) +
                          ", " +  salt_name + ")" + whereClause;

        string resultQ = string("UPDATE ") + tm->anonTableName +
                         " SET " + anonfieldName + "= " + decryptS;
        result.push_back(resultQ);

        fm->secLevelOPE = SECLEVEL::OPE;



    }

    // decrypt any fields for join

    for (list<string>::iterator it = fieldsDec.DETJoinFields.begin();
         it != fieldsDec.DETJoinFields.end(); it++) {

        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);

        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];

        if (!fm->isEncrypted) {
            continue;
        }
        if (mp) {
            assert_s(false, "join not supported for multi-user ");
        }

        string anonTableName = tm->anonTableName;
        string anonfieldName = getOnionName(fm, oDET);

        fieldType ft = fm->type;

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
                                              SECLEVEL::DET)) + ");";

        string resultQ = string("UPDATE ") +
                         tableMetaMap[table]->anonTableName +
                         " SET " + anonfieldName + "= " + decryptS;

        //cout << "adding JOIN DEC " << resultQ << "\n"; fflush(stdout);
        result.push_back(resultQ);

        tableMetaMap[table]->fieldMetaMap[field]->secLevelDET = SECLEVEL::DETJOIN;
    }

    for (list<string>::iterator it = fieldsDec.OPEJoinFields.begin();
         it != fieldsDec.OPEJoinFields.end(); it++) {
        string table, field;
        getTableField(*it, table, field, qm, tableMetaMap);
        assert_s(false, "this is not fully impl");

        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];

        //for now, do nothing
        //result.push_back(getCStr(string("UPDATE ") +
        // tableMetaMap[table]->anonTableName +
        //" SET " + tableMetaMap[table]->fieldMetaMap[field]->anonFieldNameDET
        //+ " = DECRYPT(0);")); //TODO: link in the right key here

        fm->secLevelOPE = SECLEVEL::OPEJOIN;

        if (mp) {
            assert_s(false,
                     " opejoin adjustment not supported with multi-user\n");
        }
    }

    return result;
}

//returns a list of simple queries from nested queries,
/*
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
*/
list<string>
EDBProxy::rewriteEncryptSelect(const string &query)
throw (CryptDBError)
{
    list<string> words = getSQLWords(query);
    LOG(edb) << "after sql words " << toString(words, angleBrackets);
    return rewriteSelectHelper(words);

    /*
    FieldsToDecrypt fieldsDec;

    if (!isNested(query)) {
        list<string> words = getSQLWords(query);
        LOG(edb) << "after sql words " << toString(words, angleBrackets);
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

    //cerr << "rewrite encrypt select Helper "; myPrint(simpleQ.back());
    //cerr << "\n";

    list<string> results = rewriteSelectHelper(
        simpleQ.back(), false, encqueries);
    //cerr << "helper result "; myPrint(results); cerr << "\n";
    assert_s(
        results.size() == 1,
        "there should not be any new decryption queries\n");

    decqueries.push_back(results.back());

    return decqueries;
*/
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
                                                   fm, qm, 1));

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
                                               fm, qm, 1));
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

void
EDBProxy::generateEncTables(list<OPESpec> & opes,
                unsigned int minHOM, unsigned int maxHOM,
                unsigned int randomPoolSize, string outputfile) {

    ofstream file(outputfile);

    bool isBin;

    for (list<OPESpec>::iterator it = opes.begin(); it != opes.end(); it++) {
        string table, field;
        QueryMeta qm;
        getTableField(it->fieldname, table, field, qm, tableMetaMap);

        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];
        assert_s(fm->type == TYPE_INTEGER, " enc tables only for integers ");

        string fullname = fullName(fm->anonFieldNameOPE, tm->anonTableName);

        file << fullname << " " << (it->maxv-it->minv+1) << "\n";


        for (unsigned int v = it->minv; v <= it->maxv; v++) {
            file << v << " ";
            file << cm->crypt(cm->getmkey(), StringFromVal(v), TYPE_INTEGER, fullname, SECLEVEL::PLAIN_OPE, SECLEVEL::OPE, isBin, 0) << "\n";
        }
    }

    file << "HOM " << StringFromVal(maxHOM-minHOM+1) << "\n";

    for (unsigned int v = minHOM; v <= maxHOM; v++) {
        file << v << " ";
        string enc = cm->crypt(cm->getmkey(), StringFromVal(v), TYPE_INTEGER, "", SECLEVEL::PLAIN_AGG, SECLEVEL::SEMANTIC_AGG, isBin, 0);
        file << marshallBinary(enc) << "\n";
    }

    file.close();

    cm->generateRandomPool(randomPoolSize, outputfile);

}

void EDBProxy::loadEncTables(string filename) {
    cm->loadEncTables(filename);
}

list<string>
EDBProxy::rewriteSelectHelper(list<string> words, bool isSubquery,
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
    QueryMeta qm  = getQueryMeta(cmd::SELECT, words, tableMetaMap);
    LOG(edb_v) << "after get query meta";
//    gettimeofday(&endtime, NULL);
//    cout << "get query meta" << timeInMSec(starttime, endtime) << "\n";
    //expand * in SELECT *

//    gettimeofday(&starttime, NULL);
    expandWildCard(words, qm, tableMetaMap);
    LOG(edb_v) << "after expand wildcard";
//    gettimeofday(&endtime, NULL);
//    cout << "expand wild card " << timeInMSec(starttime, endtime) << "\n";
    //=========================================================

    LOG(edb_v) << "new query is: " << toString(words, angleBrackets);

    list<string>::iterator wordsIt = words.begin();

    //gettimeofday(&starttime, NULL);

    if (mp) {
        tmkm.processingQuery = true;
        mp->prepareSelect(words, tmkm, qm, tableMetaMap);
        if (VERBOSE) { LOG(edb_v) << "done with prepare select"; }
    }

//    gettimeofday(&endtime, NULL);
//        cout << "MULTIPRINC prepare select" << timeInMSec(starttime,
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

    std::set<string> tablesAddedSalt;

    while (!equalsIgnoreCase(*wordsIt, "from")) {

        string table, field;

        if (toLowerCase(*wordsIt).compare("sum") == 0) {
            wordsIt++;
            assert_s(wordsIt->compare(
                         "(") == 0, "sum should be followed by parenthesis");
            wordsIt++;
            string fieldToAgg = *wordsIt;
            wordsIt++;
            //there may be other stuff before first parent
            string res = mirrorUntilTerm(wordsIt, words, {")"}, 0, 0);

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
                        tm->anonTableName, table, field, fm, qm) +") ";
                } else {
                    funcname = SUM_AGG;
                    resultQuery += " " + funcname + "( "  + fieldNameForQuery(
                        tm->anonTableName, table, getOnionName(fm,
                                                               oAGG),
                        fm, qm) + ", " +
                                   marshallBinary(cm->getPKInfo()) + ") ";
                }

                if (mp) {
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
                if (fmd->secLevelDET == SECLEVEL::SEMANTIC_DET) {
                    addIfNotContained(fullName(fieldD,
                                               tableD), fieldsDec.DETFields);
                }
                if (DECRYPTFIRST) {
                    resultQuery  += " " +
                                    fieldNameForQuery(
                        tableMetaMap[tableD]->anonTableName,
                        tableD, fieldD,
                        fmd, qm);

                } else {
                    resultQuery  += " " +
                                    fieldNameForQuery(
                        tableMetaMap[tableD]->anonTableName,
                        tableD,
                        getAnonNameForFilter(fmd,
                                         oDET),
                        fmd, qm);
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
                                          tableD, getAnonNameForFilter(fmd,
                                                                   oDET),
                                          fmd, qm);
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
            fm->ope_used = true;

            string anonName =
                getOnionName(fm,oOPE);

            if (fm->isEncrypted) {
                assert_s((fm->type != TYPE_TEXT),
                                     "min, max not fully implemented for text");

                if (DECRYPTFIRST) {
                    resultQuery = resultQuery + fieldNameForQuery(
                        tm->anonTableName, table2, field2, fm, qm);
                } else {
                    resultQuery = resultQuery + fieldNameForQuery(
                        tm->anonTableName, table2, anonName, fm, qm);
                }

                if (mp) {
                    resultQuery +=
                        mp->selectEncFor(table2, field2, qm, tmkm, tm,
                                         fm);
                }

                if (tableMetaMap[table2]->fieldMetaMap[field2]->secLevelOPE
                    ==
                    SECLEVEL::SEMANTIC_OPE) {
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

        //CASE: field
        string origname = *wordsIt;
        getTableField(origname, table, field, qm, tableMetaMap);

        TableMetadata * tm = tableMetaMap[table];
        FieldMetadata * fm = tm->fieldMetaMap[field];


        //cerr <<"w\n";
        LOG(edb) << "table " << table << " has encrypted? " << tm->hasEncrypted << "\n";

        if (tablesAddedSalt.find(table) == tablesAddedSalt.end()) {
            //need to add salt if new table is sensitive
            if (tm->hasEncrypted) {
                resultQuery = resultQuery + " " + tm->salt_name + " ,";
            }
            tablesAddedSalt.insert(table);
        }

        if (!fm->isEncrypted) {
            resultQuery = resultQuery + " " + fieldNameForQuery(
                tm->anonTableName, table, field, fm, qm);
             wordsIt++;
             resultQuery += processAlias(wordsIt, words);
            continue;
        }

        //CASE: encrypted field

        if (detToAll && (fm->secLevelDET == SECLEVEL::SEMANTIC_DET)) {
            addIfNotContained(fullName(field, table), fieldsDec.DETFields);
            fm->secLevelDET = SECLEVEL::DET;
        }
        resultQuery = resultQuery + " " +
                fieldNameForQuery(tm->anonTableName, table,
                        anonFieldNameForDecrypt(
                                fm), fm, qm);

        if (fm->secLevelDET == SECLEVEL::SEMANTIC_DET) {
            if (fm->has_salt) {
                resultQuery += ", " + fm->salt_name;
            } //without a salt, the table's salt will be used
        }

        if (mp) {
            resultQuery += mp->selectEncFor(table, field, qm, tmkm, tm,
                    fm);
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

    return res;
}

static bool
isNextSalt(unsigned int index, const ResType & vals, unsigned int nFields) {
    if (index >= nFields-1) {
        return false;
    }

    bool aux;
    if (isSalt(vals.names[index+1], aux)) {
        return true;
    } else {
        return false;
    }

}
//words are the keywords of expanded unanonymized queries
//words is unencrypted and unmodified query
static ResMeta
getResMeta(list<string> words, const ResType &vals, QueryMeta & qm,
           map<string, TableMetadata * > & tm, MultiPrinc * mp,
           TMKM & tmkm)
{
    LOG(edb_v) << toString(words, angleBrackets);

    ResMeta rm = ResMeta();

    size_t nFields = vals.names.size();
    rm.nFields = nFields;
    rm.nTuples = vals.rows.size();

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

        //case : salt
        bool isTableSalt;
        if (isSalt(vals.names[i], isTableSalt)) {
            rm.isSalt[i] = true;
            if (isTableSalt) {
                rm.SaltIndexes[getTableOfSalt(vals.names[i])] = i;
            } else {
                LOG(edb_v) << "field salt";
                rm.SaltIndexes[fullName(rm.field[i-1], rm.table[i-1])] = i;
            }
            rm.o[i] = oNONE;
            continue;
        }

        //case : fields we added to help with multi princ enc
        if (ignore) {
            rm.isSalt[i] = false;
            ignore = false;
            continue;
        }

        //case : fields requested by user

        LOG(edb_v) << "field " << vals.names[i];

        rm.isSalt[i] =  false;
        rm.nTrueFields++;

        string currToken = *wordsIt;
        //cerr << "--> " << currToken << "\n";

        //subcase: aggregate
        if (isAgg(*wordsIt)) {
            //cerr << "before process agg \n";
            rm.namesForRes[i] =
                processAgg(wordsIt, words, rm.field[i], rm.table[i], rm.o[i],
                           qm, tm, 0);
            if (mp) {
                mp->processReturnedField(i, isNextSalt(i, vals, (uint) nFields),
                                         fullName(rm.field[i], rm.table[i]),
                                         rm.o[i], tmkm, ignore);
            }

//            cerr << "field, " << rm.field[i] << " table  " <<
// rm.table[i] << " onion " << rm.o[i] << " nameForRes " << rm.namesForRes[i]
// << "\n";
            continue;
        }

        //subcase: field

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

        if (mp) {
            mp->processReturnedField(i, isNextSalt(i, vals, (uint) nFields),
                                     fullName(rm.field[i], rm.table[i]),
                                     rm.o[i], tmkm, ignore);
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

    return rm;
}

ResType
EDBProxy::rewriteDecryptSelect(const string &query, const ResType &dbAnswer)
{

    //cerr << "in decrypt \n";

    //===== PREPARE METADATA FOR DECRYPTION ================

    //parse
    list<string> words = getSQLWords(query);

    QueryMeta qm = getQueryMeta(cmd::SELECT, words, tableMetaMap);
    auto ANON = cleanup([&qm]() { qm.cleanup(); });

    expandWildCard(words, qm, tableMetaMap);


    if (VERBOSE) {
        LOG(edb) << "Raw results from the server to decrypt:";
        printRes(dbAnswer);
    }

    TMKM tmkm;
    if (mp) {
        tmkm.processingQuery = false;
        // extracts enc-for principals from queries
        mp->prepareSelect(words, tmkm, qm, tableMetaMap);
    }

    ResMeta rm = getResMeta(words, dbAnswer, qm, tableMetaMap, mp, tmkm);
    auto ANON = cleanup([&rm]() { rm.cleanup(); });

    //====================================================

    LOG(edb) << "done with res meta";

    //prepare the result

    ResType rets;
    rets.rows.resize(rm.nTuples);

    size_t nFields = rm.nFields;
    size_t nTrueFields = rm.nTrueFields;

    //fill in field names and types
    rets.names.resize(nTrueFields);
    rets.types.resize(nTrueFields);

    unsigned int index0 = 0;
    for (unsigned int i = 0; i < nFields; i++) {
        if ((!rm.isSalt[i]) && (!mp || tmkm.returnBitMap[i])) {
            rets.names[index0] = rm.namesForRes[i];
            if (rm.o[i] == oNONE) { // val not encrypted
                rets.types[index0] = dbAnswer.types[i]; //return the type from the mysql server
            } else {
                rets.types[index0] = tableMetaMap[rm.table[i]]->fieldMetaMap[rm.field[i]]->mysql_type;
            }
            index0++;
        }
    }


    for (unsigned int i = 0; i < rm.nTuples; i++)
    {
        rets.rows[i].resize(nTrueFields);
        unsigned int index = 0;


        for (unsigned int j = 0; j < nFields; j++) {

            if (rm.isSalt[j]) {             // this is salt
                LOG(edb) << "salt";
                continue;
            }

            // ignore this field if it was requested additionally for multi
            // princ
            if (mp) {
                if (!tmkm.returnBitMap[j]) {
                    LOG(edb) << "ignore";
                    continue;
                }
            }

            // CASE: this is a typical value

            string table = rm.table[j];
            string field = rm.field[j];
            string fullname = fullName(field, table);

            LOG(edb) << fullname;

            if (rm.o[j] == oNONE) {             //not encrypted
                LOG(edb) << "its not enc";
                rets.rows[i][index] = dbAnswer.rows[i][j];
                index++;
                continue;
            }

            //CASE: the field is encrypted
            TableMetadata * tm = tableMetaMap[table];
            FieldMetadata * fm = tm->fieldMetaMap[field];

            string fullAnonName = fullName(getOnionName(fm,
                                                        rm.o[j]),
                                           tm->anonTableName);
            bool isBin;
            rets.rows[i][index].null = dbAnswer.rows[i][j].null;
            rets.rows[i][index].type = fm->mysql_type;

            if (!rets.rows[i][index].null) {

                //get salt to use
                uint64_t salt = 0;
                if (fm->has_salt && (rm.SaltIndexes.find(fullname) != rm.SaltIndexes.end())) {
                    salt = valFromStr(dbAnswer.rows[i][rm.SaltIndexes[fullname]].data);

                } else { //maybe there is table salt
                    if (rm.SaltIndexes.find(tm->anonTableName) != rm.SaltIndexes.end()) {
                        salt = valFromStr(dbAnswer.rows[i][rm.SaltIndexes[tm->anonTableName]].data);

                    }
                }

                rets.rows[i][index].data =
                        crypt(dbAnswer.rows[i][j].data, fm->type,
                                fullName(field, table), fullAnonName,
                                getLevelForOnion(fm, rm.o[j]),
                                getLevelPlain(rm.o[j]), salt,
                                tmkm, isBin, dbAnswer.rows[i]);

            }
            index++;
        }
    }
    return rets;
}

// It removes "%" from the search constant - we want to consider them
// at some point
// e.g. LIKE "ana%" means that 'ana' should be at the beginning
static string
getLIKEToken(const string &s)
{
    string res = removeApostrophe(s);
    unsigned int len = (uint) res.length();

    if (res[0]=='%') {
        res = res.substr(1, --len);
    }
    if (res[len-1] == '%') {
        res = res.substr(0, --len);
    }

    LOG(edb_v) << "search token is <" << res << ">\n";
    return toLowerCase(res);
}

string
EDBProxy::processOperation(string operation, string op1, string op2,
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
        if (mp) {
            assert_s(false,
                     "MULTIPRINC first operand of operation should be field");
        }
        assert_s(false, "this condition needs rewriting");
        /*AES_KEY * aesKeyJoin =
            CryptoManager::get_key_DET(cm->getKey("join", SECLEVEL::DETJOIN));
        string res = "";
        res =
            strFromVal(cm->encrypt_DET((uint64_t) valFromStr(op1),
                                        aesKeyJoin)) + " IN " +
            encryptedsubquery + " ";
        return res; */
        return "";
    }

    // the first operand is a field

    getTableField(op1, table1, field1, qm, tableMetaMap);

    string anonTable1 = tableMetaMap[table1]->anonTableName;
    string anonField1, anonOp1;

    FieldMetadata * fm1 = tableMetaMap[table1]->fieldMetaMap[field1];

    assert_s(!fm1->INCREMENT_HAPPENED, "field " + field1 + " has already been used in an aggregate so predicates cannot be evaluated any more ");

    fieldType ftype1 = fm1->type;

    string res = "";

    LOG(edb) << "operands " << op1 << " " << op2;
    if (isField(op1) && isField(op2)) {    //join
        LOG(edb_v) << "IN JOIN";
        if (mp) {
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

        assert_s(!fm2->INCREMENT_HAPPENED, "field " + field3 + " has already been used in an aggregate so predicates cannot be evaluated any more ");

        string anonTable2 = tm2->anonTableName;
        string anonField2 = fm2->anonFieldNameDET;
        string anonOp2 = fullName(anonField2, anonTable2);

        res =
            " "+fieldNameForQuery(anonTable1, table1, anonField1, fm1,
                              qm) + " " + operation + " " +
            fieldNameForQuery(anonTable2, table3, anonField2, fm2,
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
              fieldNameForQuery(anonTable1, table1, anonField1, fm1,
                                qm) + " " +  operation + " ";

        if (Operation::isIN(operation)) {
            res = res + encryptedsubquery + " ";
            return res;
        }

        res = res + dataForQuery(op2, ftype1, fullName(field1,
                                                table1), anonOp1, SECLEVEL::PLAIN_DET,
                          highestEq(sl), 0, tmkm);

        return res;

    }

    if (Operation::isILIKE(operation)) {     //DET

        /* Method 2 search: SWP */
         LOG(edb_v) << "IS LIKE/ILIKE";

        anonField1 = fm1->anonFieldNameSWP;
        string anonfull = fullName(anonField1,
                                   tableMetaMap[table1]->anonTableName);

        if (removeApostrophe(op2).length() == 0) {

            res += anonField1 + " LIKE '' ";

        } else {
            res += SEARCHSWP"(";

            Binary key = Binary(cm->getKey(cm->getmkey(), anonfull, SECLEVEL::SWP));

            Token t = CryptoManager::token(key, Binary(getLIKEToken(op2)));

            res +=
                    marshallBinary(string((char *)t.ciph.content,
                            t.ciph.len)) + ", " +
                            marshallBinary(string((char *)t.wordKey.content,
                                    t.wordKey.len)) +  ", " +  anonField1 + ") = 1; ";
        }

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
                                               table1), anonOp1, SECLEVEL::PLAIN_DET,
                          SECLEVEL::DET, 0, tmkm);

           res = res + ", " + anonOp1 + ") ";

           return res;
         */

    }

    LOG(edb_v) << "IS OPE";
    //operation is OPE

    anonField1 = tableMetaMap[table1]->fieldMetaMap[field1]->anonFieldNameOPE;
    anonOp1 = fullName(anonField1, anonTable1);

    FieldMetadata * fm = tableMetaMap[table1]->fieldMetaMap[field1];

    assert_s(Operation::isOPE(
                 operation), " expected OPE , I got " + operation + " \n");

    string fieldname;
    if (DECRYPTFIRST) {
        fieldname = fieldNameForQuery(anonTable1, table1, field1, fm1, qm);
    } else {
        fieldname = fieldNameForQuery(anonTable1, table1, anonField1, fm1,
                                      qm);
    }

    //cout << "key used to get to OPE level for "<< tokenOperand << "is " <<
    //  CryptoManager::marshallKey(cm->getKey(tokenOperand, SECLEVEL::OPE)) << "\n";
    res = res + " " + fieldname + " " +  operation + " " +
          dataForQuery(op2, fm->type, fullName(field1, table1),
                anonOp1, SECLEVEL::PLAIN_OPE, SECLEVEL::OPE, 0, tmkm);

    return res;
}

list<string>
EDBProxy::rewriteEncryptDrop(const string &queryI)
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
    delete tableMetaMap[tableName];
    tableMetaMap.erase(tableName);

    tableNameMap.erase(anonTableName);
#if NOTDEMO
    Connect pconn( meta_db.conn() );
    pconn.execute( "BEGIN;" );

    string delete_from_table_info( "DELETE FROM table_info WHERE " );

    pconn.execute( delete_from_table_info
                  + "name='"      + tableName     + "' AND "
                  + "anon_name='" + anonTableName + "'"
                  + ";" );

    pconn.execute( "COMMIT;" );
#endif
    list<string> resultList;
    resultList.push_back(result);
    return resultList;
}

list<string>
EDBProxy::rewriteEncryptDelete(const string &query)
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

    if (mp) {
        if (mp->checkPsswd(cmd::DELETE, words)) {
            return list<string>();
        }
    }

    //first figure out what tables are involved to know what fields refer to
    QueryMeta qm = getQueryMeta(cmd::DELETE, words, tableMetaMap);
    auto ANON = cleanup([&qm]() { qm.cleanup(); });

    TMKM tmkm;
    if (mp) {
        tmkm.processingQuery = true;
        mp->getEncForFromFilter(cmd::DELETE, words, tmkm, qm, tableMetaMap);
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

    return res;
}

string
EDBProxy::processValsToInsert(string field, FieldMetadata * fm, string table, TableMetadata * tm, uint64_t salt,
                               string value, TMKM & tmkm, bool null)
{

    if (tm->ai.field == field) {
        tm->ai.incvalue = max((uint64_t) tm->ai.incvalue, valFromStr(value));
    }

    if (!fm->isEncrypted) {
        return value;
    }

    // all fields encrypted

    /* XXX */
    if (equalsIgnoreCase(value, "null")) {
        null = true;
    }

   /* if (DECRYPTFIRST) {
        string fullname = fullName(field, table);
        fieldType type = fm->type;
        string anonTableName = tableMetaMap[table]->anonTableName;

        if (null)
            return "NULL";
        if (type == TYPE_INTEGER) {
            AES_KEY * key = CryptoManager::get_key_DET(dec_first_key);
            string res =
                    strFromVal(CryptoManager::encrypt_DET(valFromStr(value),
                            key));
            return res;
        } else {
            assert_s(type == TYPE_TEXT, "given unexpected type");
            AES_KEY * key = CryptoManager::get_key_SEM(dec_first_key);
            string ptext = removeApostrophe(value);
            string cipher = CryptoManager::encrypt_SEM(ptext, key, 0);
            return marshallBinary(cipher);
        }
    }
*/
    string res =  "";

    string fullname = fullName(field, table);

    string anonTableName = tm->anonTableName;

    if (null) {
        if (mp) {
            assert_s(!mp->isPrincipal(fullname), "principal in multi-princ should not be null");
        }
        res += " NULL ";    /* DET */
        if (fm->has_ope) {
            res += ", NULL ";
        }
        if (fm->has_agg) {
            res += ", NULL ";
        }
        if (fm->has_search) {
            res += ", NULL ";
        }
        if (fm->has_salt) {
            res += ", 0 ";
        }
    } else {

        uint64_t mySalt = salt;

        if (fm->has_salt) {
            mySalt = randomValue();
        }

        res +=  " " +
               dataForQuery(value, fm->type, fullname,
                     fullName(fm->anonFieldNameDET,
                              anonTableName), SECLEVEL::PLAIN_DET, fm->secLevelDET,
                     mySalt, tmkm);

        LOG(edb_v) << "just added key from crypt";

        if (fm->has_ope) {
            res += ", " +
                   dataForQuery(value, fm->type, fullname,
                         fullName(fm->anonFieldNameOPE,
                                  anonTableName), SECLEVEL::PLAIN_OPE, fm->secLevelOPE,
                         mySalt, tmkm);

        }

        if (fm->has_agg) {
            res += ", " +
                   dataForQuery(value, fm->type, fullname,
                         fullName(fm->anonFieldNameAGG,
                                  anonTableName), SECLEVEL::PLAIN_AGG, SECLEVEL::SEMANTIC_AGG,
                         mySalt, tmkm);
        }

        if (fm->has_search) {
            res += ", " +
                   dataForQuery(value, fm->type, fullname,
                         fullName(fm->anonFieldNameSWP,
                                  anonTableName), SECLEVEL::PLAIN_SWP, SECLEVEL::SWP,
                         mySalt, tmkm);
        }

        if (fm->has_salt) {
            res+= ", " + StringFromVal(mySalt);
        }

    }

    return res;

}

// returns the value we should insert for a field for which the INSERT
// statement does not specify a value
static pair<string, bool>
getInitValue(TableMetadata * tm, FieldMetadata * fm, string field, string & insid_query)
{
    insid_query = "";
    // FieldMetadata * fm = tm->fieldMetaMap[field];

    //check if field has autoinc
    if (tm->ai.field == field) {
        ++tm->ai.incvalue;
        LOG(edb) << "using autoincrement value" << tm->ai.incvalue;
        insid_query = "SELECT last_insert_id("+ StringFromVal(tm->ai.incvalue) + ");";
        return make_pair(StringFromVal(tm->ai.incvalue), false);
    }

    // TODO: record and use default values here

    // check if it is not null
    if (fm->can_be_null) {
        return make_pair("", true);
    } else { //cannot be null
        if (fm->type == TYPE_TEXT) {
            return make_pair("", false);
        } else {
            return make_pair("0", false);
        }
    }

}

list<string>
EDBProxy::rewriteEncryptInsert(const string &query)
throw (CryptDBError)
{

    LOG(edb_v) << "Query: " << query;

    list<string> queries;

    list<string> words = getSQLWords(query);

    TMKM tmkm;

    //struct timeval starttime, endtime;
    //gettimeofday(&starttime, NULL);
    if (mp) {
        tmkm.processingQuery = true;
        //if this is the fake table providing user passwords, ignore query
        if (mp->checkPsswd(cmd::INSERT, words)) {
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

    resultQuery = resultQuery + tm->anonTableName + " ";
    roll<string>(wordsIt, 1);

    std::set<string> fieldsIncluded;
    list<string> fields;
    list<string> encFieldsToAdd;
    list<string> princsToAdd;
    list<string>::iterator addit;
    list<string> overallFieldNames;

    size_t noFieldsGiven = 0;

    /***
     * Fields in insert are of these types:
     *
     * Regular fields: -- fields for which a value is provided in the insert
     * princsToAdd : -- fields for which no value is specified in the insert yet
     *               -- they are principals (in particular, not encrypted) and hence cannot be left NULL
     *               -- these fields must be auto_increment if they are not specified
     * encFieldsToAdd: -- fields for which a value is not specified in the insert, are encrypted,
     *                  and cannot be NULL
     */


    // a list of fields is specified
    if (wordsIt->compare("(") == 0) {
        //new order for the fields
        resultQuery = resultQuery + " (  ";

        if (tm->hasEncrypted) {
            resultQuery += " " + tm->salt_name + ", ";
        }

        wordsIt++;

        // add all regular fields to be inserted
        while (wordsIt->compare(")") != 0) {
            string fieldname = *wordsIt;
            fields.push_back(fieldname);
            fieldsIncluded.insert(fieldname);
            assert_s(tm->fieldMetaMap.find(
                             fieldname) != tm->fieldMetaMap.end(),
                         "invalid field or you forgot keyword 'values' ");
            FieldMetadata * fm = tm->fieldMetaMap[fieldname];
            resultQuery = resultQuery + " " + processInsert(*wordsIt, table,
                                                            fm, tm);
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

        //cerr << "fieldNames are " << toString(tm->fieldNames, angleBrackets) << "\n";
        //check if we need to add any principal or encrypted field
        for (addit = tm->fieldNames.begin(); addit!=tm->fieldNames.end();
             addit++) {
            if (fieldsIncluded.find(*addit) == fieldsIncluded.end()) {
                if (tm->fieldMetaMap[*addit]->isEncrypted)  {

                    encFieldsToAdd.push_back(*addit);
                    LOG(edb) << "encfield to add " << *addit;

                } else {

                    if (mp) {
                        if (mp->isPrincipal(fullName(*addit, table))) {
                            LOG(edb_v) << "add to princs " << *addit;
                            princsToAdd.push_back(*addit);
                        }
                    }

                }
            }
        }

        //add fields names from encFieldsToAdd
        for (addit = encFieldsToAdd.begin(); addit != encFieldsToAdd.end();
             addit++) {
            string addToQuery = processInsert(*addit, table, tm->fieldMetaMap[*addit], tm);
            LOG(edb) << " encfield " << *addit << " adds to query " << addToQuery;
            resultQuery += ", " + addToQuery;
            fields.push_back(*addit);
        }

        if (mp) {
            //add fields names from princsToAdd
            for (addit = princsToAdd.begin(); addit != princsToAdd.end();
                 addit++) {
                resultQuery += ", " + processInsert(*addit, table, tm->fieldMetaMap[*addit], tm);
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

    //create list of all values to add
    while (wordsIt != words.end()) {
        wordsIt++;
        resultQuery += " ( ";

        //collect all values in vals

        list<pair<string, bool> > valnulls;
        list<string>::iterator fieldIt = fields.begin();

        //add encryptions of the fields
        for (unsigned int i = 0; i < noFieldsGiven; i++) {
            valnulls.push_back(make_pair(*wordsIt, false));
            wordsIt++;
            checkStr(wordsIt, words, ",",")");
        }
        //we now need to add fields from encFieldsToAdd
        for (addit = encFieldsToAdd.begin(); addit != encFieldsToAdd.end();
             addit++) {
            string field = *addit;
            string insid_query;
            valnulls.push_back(getInitValue(tm, tm->fieldMetaMap[field], field, insid_query));
            if (insid_query != "") {
                queries.push_back(insid_query);
            }
        }
        //cerr << "BB\n";

        if (mp) {
            //we now need to add fields from princsToAdd
            for (addit = princsToAdd.begin(); addit != princsToAdd.end();
                 addit++) {
                string field = *addit;
                string insid_query;
                valnulls.push_back(getInitValue(tm, tm->fieldMetaMap[field], field, insid_query));
                if (insid_query != "") {
                    queries.push_back(insid_query);
                }
            }
            //insert any new speaksfor instances
            LOG(edb_v) << "before insert relations";
            mp->insertRelations(valnulls, table, fields, tmkm);
        }

        LOG(edb_v) << "noFieldsGiven " << noFieldsGiven;
        LOG(edb_v) << "fiels have " << fields.size();
        LOG(edb_v) << "valnulls have " << valnulls.size();

        //cerr << "CC \n";
        uint64_t salt = 0;

        if (tableMetaMap[table]->hasEncrypted) {
            //rand field
            salt =  randomValue();
            resultQuery =  resultQuery + strFromVal(salt) + ", ";
        }

        auto valIt = valnulls.begin();
        fieldIt = fields.begin();

        //now add all values encrypted
        for (unsigned int i = 0; i < noFieldsGiven; i++) {
            string fieldName = *fieldIt;
            string value = removeApostrophe(valIt->first);

            //cerr << "processing for field " << *fieldIt << " with given
            // value " << *valIt << "\n";
            resultQuery += processValsToInsert(*fieldIt, tm->fieldMetaMap[*fieldIt], table, tm, salt, valIt->first,
                                               tmkm, valIt->second);
            valIt++;
            fieldIt++;
            if (i < noFieldsGiven-1) {
                resultQuery += ", ";
            }
        }

        //we now need to add fields from encFieldsToAdd
        for (addit = encFieldsToAdd.begin(); addit != encFieldsToAdd.end();
             addit++) {
            string field = *addit;
            resultQuery += ", " + processValsToInsert(field, tm->fieldMetaMap[field], table, tm, salt,
                                                      valIt->first,
                                                      tmkm, valIt->second);
            valIt++;
        }

        if (mp) {
            //we now need to add fields from princsToAdd
            for (addit = princsToAdd.begin(); addit != princsToAdd.end();
                 addit++) {
                string field = *addit;
                string fullname = fullName(field, table);
                resultQuery += ", " +
                               processValsToInsert(field, tm->fieldMetaMap[field], table, tm, salt, valIt->first,
                                                   tmkm, valIt->second);
                valIt++;
            }
        }

        assert_s(valIt == valnulls.end(), "valIt should have been the end\n");
        valnulls.clear();

        assert_s(wordsIt->compare(")") == 0, "missing )");
        resultQuery += ")";
        wordsIt++;

        resultQuery += checkStr(wordsIt, words, ",", ")");

    }

    assert_s(wordsIt == words.end(), "invalid text after )");

    resultQuery = resultQuery + ";";

    queries.push_back(resultQuery);
    return queries;
}

list<string>
EDBProxy::rewriteEncryptCommit(const string &query)
throw (CryptDBError)
{

    list<string> words = getSQLWords(query);


    list<string>::iterator wordsIt = words.begin();


    if (words.size() == 1) {
       return list<string>(1, "commit;");
    }


    if (mp) {
        wordsIt++;
        if (equalsIgnoreCase(*wordsIt, "annotations")) {
            wordsIt++;
            assert_s(
                wordsIt == words.end(),
                "nothing should come after <commit annotations>");
            mp->commitAnnotations();
            return list<string>();
        }
    }


    assert_s(wordsIt==words.end(), "nothing should come after commit;");


    return list<string>(1, "commit;");
}

list<string>
EDBProxy::rewriteEncryptBegin(const string &query)
throw (CryptDBError)
{
    return list<string>(1, "begin;");
}

/******
 *
 *      INDEX CREATION POLICY
 *
 *
 *  -- If field does not use OPE, create index on DET
 *  -- If field uses OPE:
 *     -- if index is requested solely on this field
 *               -- if field has equijoin, create index on both OPE and DET
 *               -- if field does not have equijoin, create index on OPE only
 *    -- if index is requested on a list of fields, including this field
 *               -- if field has equijoin,
 *
 */

list<string>
EDBProxy::rewriteEncryptAlter(const string &query)
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
bool
EDBProxy::considerQuery(command com, const string &query)
{
    switch (com) {
    case cmd::CREATE: {
        list<string> words = getSQLWords(query);
        list<string>::iterator wordsIt = words.begin();
        wordsIt++;
        if (equalsIgnoreCase(*wordsIt, "function")) {
            return false;
        }
        break;
    }
    case cmd::UPDATE: {
        if (mp) {
            list<string> words = getSQLWords(query);
            auto it_update = itAtKeyword(words, "update");
            it_update++;
            string table_name = *it_update;
            auto table_info = tableMetaMap.find(table_name);
            //if we can't find this table in the map, or none of its fields are encrypted
            // don't consider
            if (table_info == tableMetaMap.end() || !table_info->second->hasSensitive) {
                LOG(edb_v) << "don't consider " << query << endl;
                return false;
            }
        }
        break; 
    }
    case cmd::INSERT: {
        list<string> words = getSQLWords(query);
        if (contains("select", words)) {
            LOG(warn) << "given nested query!";
            return false;
        }
        if (mp) {
            auto it_insert = itAtKeyword(words, "insert");
            it_insert++;
            it_insert++;
            string table_name = *it_insert;
            //if active_users, must consider
            if (table_name.find(PWD_TABLE_PREFIX) != string::npos) {
                break;
            }
            auto table_info = tableMetaMap.find(table_name);
            //if we can't find this table in the map, or none of its fields are encrypted
            // don't consider
            if (table_info == tableMetaMap.end() || !table_info->second->hasSensitive) {
                LOG(edb_v) << "don't consider " << query << endl;
                return false;
            }
        }
        break; 
    }
    case cmd::SELECT: {
        list<string> words = getSQLWords(query);
        //for speed
        if (!contains("from", words)) {
            return false;
        }

        if (mp) {
            auto it_from = itAtKeyword(words, "from");
            it_from++;
            bool table_sense = false;
            while(it_from != words.end() && !isKeyword(*it_from)) {
                auto table_info = tableMetaMap.find(*it_from);
                if (table_info != tableMetaMap.end() && table_info->second->hasEncrypted) {
                    table_sense = true;
                }
                it_from++;
            }
            //it none of the tables selected from are sensitive, ignore the query
            if (!table_sense) {
                return false;
            }

            break;
        }
    }
    case cmd::DROP: {
        list<string> words = getSQLWords(query);
        list<string>::iterator wordsIt = words.begin();
        wordsIt++;
        if (equalsIgnoreCase(*wordsIt, "function")) {
            return false;
        }
        break;
    }
    case cmd::DELETE: {
        if (mp) {
            list<string> words = getSQLWords(query);
            auto it_delete = itAtKeyword(words, "delete");
            it_delete++;
            it_delete++;
            string table_name = *it_delete;
            //if active_users, must consider
            if (table_name.find(PWD_TABLE_PREFIX) != string::npos) {
                break;
            }
            auto table_info = tableMetaMap.find(table_name);
            //if we can't find this table in the map, or none of its fields are encrypted
            // don't consider
            if (table_info == tableMetaMap.end() || !table_info->second->hasSensitive) {
                LOG(edb_v) << "don't consider " << query << endl;
                return false;
            }
        }
        break; 
    }
    case cmd::BEGIN: {
        return true;
    }
    case cmd::COMMIT: {
        if (DECRYPTFIRST) {
            return true;
        }
        list<string> words = getSQLWords(query);
        list<string>::iterator wordsIt = words.begin();
        wordsIt++;
        if (wordsIt != words.end() && equalsIgnoreCase(*wordsIt, "annotations")) {
            return true;
        }
        LOG(edb_v) << "commit";
        return false;
    }
    case cmd::TRAIN: {
        LOG(edb_v) << "training";
        return true;
    }
    case cmd::ALTER: {
        LOG(edb_v) << "alter";
        if (DECRYPTFIRST) {
            return true;
        }

        return false;
    }
    default:
    case cmd::OTHER: {
        LOG(edb_v) << "other";
        return false;
    }
    }

    return true;
}

list<string>
EDBProxy::rewriteEncryptQuery(const string &query, bool &considered)
throw (CryptDBError)
{
    static default_enabler ena;
    if (ena.enabled()) {
        static int callCount;
        if (!(callCount++ % 1000)) {
            perfsum_base::printall(30);
            perfsum_base::resetall();
        }
    }

    ANON_REGION(__func__, &perf_cg);

    considered = true;
    if (!isSecure) {
        considered = false;
        return list<string>(1, query);
    }

    //It is secure

    command com = getCommand(query);

    LOG(edb) << "-------------------";
    LOG(edb) << "Query: " << query;

    //some queries do not need to be encrypted
    if (!considerQuery(com, query)) {
        LOG(edb_v) << "query not considered: " << query;
        // cerr << "query not considered : " << query;
        list<string> res;
        res.push_back(query);
        considered = false;
        return res;
    }

    //dispatch query to the appropriate rewriterEncryptor
    switch (com) {
    case cmd::CREATE: {return rewriteEncryptCreate(query); }
    case cmd::UPDATE: {return rewriteEncryptUpdate(query); }
    case cmd::INSERT: {return rewriteEncryptInsert(query); }
    case cmd::SELECT: {return rewriteEncryptSelect(query); }
    case cmd::DROP: {return rewriteEncryptDrop(query); }
    case cmd::DELETE: {return rewriteEncryptDelete(query); }
    case cmd::TRAIN: {return rewriteEncryptTrain(query);}
    case cmd::BEGIN: {
        if (DECRYPTFIRST)
            return list<string>(1, query);

        return rewriteEncryptBegin(query);
    }
    case cmd::COMMIT: {
        if (DECRYPTFIRST)
            return list<string>(1, query);

        return rewriteEncryptCommit(query);
    }
    case cmd::ALTER: {
        if (DECRYPTFIRST)
            return list<string>(1, query);

        return rewriteEncryptAlter(query);
    }
    case cmd::OTHER:
    default: {
        //cerr << "other query\n";
        if (DECRYPTFIRST)
            return list<string>(1, query);
    }
    }
    //cerr << "e" << endl;
    assert_s(false, "invalid control path");
    return list<string>();
}

ResType
EDBProxy::decryptResults(const string &query, const ResType &dbAnswer)
{
    if (DECRYPTFIRST) {
        return dbAnswer;
    }

    if (dbAnswer.rows.size() == 0)
        return dbAnswer;

    // some queries do not need to be encrypted
    command com = getCommand(query);
    if (!considerQuery(com, query)) {
      //cerr << "do not consider query: " << query;
        return dbAnswer;
    }

    switch (com) {
    case cmd::SELECT:
        return rewriteDecryptSelect(query, dbAnswer);

    default:
        return dbAnswer;
    }
}


void
EDBProxy::dropTables()
{

    if (dropOnExit) {
        map<string, TableMetadata *>::iterator it = tableMetaMap.begin();

        for (; it != tableMetaMap.end(); it++) {

            if (VERBOSE) {cerr<< "drop table " << it->first << "\n"; }
            conn->execute("DROP TABLE " + it->second->anonTableName + " ;");
        }
    }
}

ResType
EDBProxy::decryptResultsWrapper(const string &query, DBResult * dbres)
{
    command comm = getCommand(query);

    if (comm == cmd::SELECT) {
        LOG(edb) << "going in select";
        ResType rets = decryptResults(query, dbres->unpack());

        if (VERBOSE) {
            LOG(edb) << "Decrypted results:";
            printRes(rets);
        }

        return rets;
    }

    LOG(edb) << "return empty results";
    //empty result
    return ResType();
}

ResType
EDBProxy::execute(const string &query)
{
    Timer t;
    DBResult * res = 0;

    LOG(edb_query_plain) << "Query: " << query;

    if (!isSecure) {

        if (!conn->execute(query, res)) {
            fprintf(stderr, "%s failed: %s \n", query.c_str(), conn->getError(
                        ).c_str());
            return ResType(false);
        }

        if (getCommand(query) == cmd::SELECT) {
            ResType r = res->unpack();
            delete res;
            return r;
        } else {
            delete res;
            return ResType();
        }
    }

    //secure

    list<string> queries;

    try {
        bool temp;
        queries = rewriteEncryptQuery(query, temp);
        LOG(edb_perf) << "rewrite latency: " << t.lap();
    } catch (CryptDBError se) {
        LOG(warn) << "problem with query " << query << ": " << se.msg;
        return ResType(false);
    }

    if (queries.size() == 0)
        return ResType();

    auto queryIt = queries.begin();

    size_t noQueries = queries.size();
    size_t counter = 0;

    for (; queryIt != queries.end(); queryIt++) {
        counter++;

        LOG(edb_query) << "Translated query: " << *queryIt;

        DBResult * reply;
        reply = NULL;

        if (!conn->execute(*queryIt, reply)) {
            LOG(warn) << "query failed: " << *queryIt;
            return ResType(false);
        }

        LOG(edb_perf) << "execute latency: " << t.lap();

        if (counter < noQueries) {
            delete reply;
            //do nothing

        } else {
            assert_s(counter == noQueries, "counter differs from noQueries");

            LOG(edb) << "onto decrypt results";
            ResType rets;
            try {
                rets = decryptResultsWrapper(query, reply);
            } catch (CryptDBError e) {
                LOG(warn) << e.msg;
                queries.clear();
                delete reply;
                return ResType(false);
            }

            LOG(edb) << "done with decrypt results";
            LOG(edb_perf) << "decrypt latency: " << t.lap();
            queries.clear();
            delete reply;
            return rets;

        }

    }

    assert_s(false, "invalid control path");
    return ResType(false);
}

void
EDBProxy::exit()
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

EDBProxy::~EDBProxy()
{
    this->exit();

    for (auto i = tableMetaMap.begin(); i != tableMetaMap.end(); i++)
        delete i->second;

    delete cm;
    delete mp;
    delete conn;
}




void
EDBProxy::outputOnionState()
{
    for (map<string, TableMetadata *>::iterator tm = tableMetaMap.begin();
         tm != tableMetaMap.end(); tm++) {
        cerr<<"table: " << tm->first << " " << tm->second->anonTableName << "\n";
        if (tm->second->hasEncrypted) {
            for (map<string, FieldMetadata *>::iterator fm =
                     tm->second->fieldMetaMap.begin();
                 fm != tm->second->fieldMetaMap.end(); fm++) {
                FieldMetadata * f = fm->second;
                if (f->isEncrypted) {
                    printf("%-26s DET:%-20s", fullName(f->fieldName, tm->first).c_str(), f->anonFieldNameDET.c_str());
                    printf(" %-14s", levelnames[(int) f->secLevelDET].c_str());
                    if (f->has_ope)
                        printf(" %-14s", levelnames[(int) f->secLevelOPE].c_str());
                    if (f->has_agg) {
                        printf(" %-14s", levelnames[(int) SECLEVEL::SEMANTIC_AGG].c_str());
                    }
                    if (f->has_search) {
                        printf(" %-14s", levelnames[(int) SECLEVEL::SWP].c_str());
                    }
                    if (f->has_salt) {
                        printf(" %-14s", f->salt_name.c_str());
                    }
                    cout << "\n";
                }
            }
        }
    }
}


void
EDBProxy::runQueries(string queryFile, bool execquery)
throw (CryptDBError)
{
    ifstream infile(queryFile);

    assert_s(infile.is_open(), "cannot open file " + queryFile);

    string query;
    list<string> queries;
    while (!infile.eof()) {
        query = getQuery(infile);

        if (query.length() == 0) {
            continue;
        }

        if (query.length() > 0) {
            bool temp;
            queries = rewriteEncryptQuery(query+";",temp);
            if (execquery) {
                for (auto it = queries.begin(); it != queries.end(); it++) {
                    assert_s(conn->execute(*it), "failed to execute query " + *it);
                }
            }
        }
    }

    infile.close();

}

void
EDBProxy::setStateFromTraining() {
    //go through all tables and all fields, and set "has_[onion]" to false if "used_[onion]" is false except for DET

    for (auto tit = tableMetaMap.begin(); tit != tableMetaMap.end(); tit++) {
        TableMetadata * tm = tit->second;
        for (auto fit = tm->fieldMetaMap.begin(); fit != tm->fieldMetaMap.end(); fit++) {
            FieldMetadata * fm = fit->second;
            fm->has_ope = fm->ope_used;
            fm->has_search = fm->search_used;
            fm->has_agg = fm->agg_used;

            //determine if field needs its own salt
            if (fm->isEncrypted && fm->update_set_performed && ((fm->secLevelDET == SECLEVEL::SEMANTIC_DET) || (fm->secLevelOPE == SECLEVEL::SEMANTIC_OPE))) {
                fm->has_salt = true;
            } else {
                fm->has_salt = false;
            }
        }
    }

}

list<string>
EDBProxy::rewriteEncryptTrain(const string & query) {
    //parse query
    list<string> words = getSQLWords(query);

    //cerr << "training\n";
    assert_s(words.size() == 5, "invalid number of inputs to train, expecting: TRAIN are_all_fields_encrypted createsfile queryfile execute?");

    list<string>::iterator it = words.begin();
    string enc = *(++it);
    if (enc != "0") {
        allDefaultEncrypted = true;
    }
    string createsfile = *(++it);
    string queryfile = *(++it);
    bool doexec = (valFromStr(*(++it)) != 0);

    //create tables
    runQueries(createsfile, 0);

    //train on query file
    runQueries(queryfile, 0);

    //update onion state
    setStateFromTraining();

    //recreate tables
    overwrite_creates = true;
    runQueries(createsfile, doexec);
    overwrite_creates = false;


    outputOnionState();

    return list<string>();
}

string
EDBProxy::dataForQuery(const string &data, fieldType ft,
                        const string &fullname, const string &anonfullname,
                        SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                        //optional, for MULTIPRINC
                        TMKM &tmkm, const vector<SqlItem> &res)
{
    bool isBin = false;
    string ndata = crypt(data, ft, fullname, anonfullname,
                         fromlevel, tolevel, salt, tmkm, isBin, res);

    if (isBin) {
        return marshallBinary(ndata);
    } else {
        return ndata;
    }
}

string
EDBProxy::crypt(string data, fieldType ft, string fullname,
                 string anonfullname,
                 SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt,
                 //optional, for MULTIPRINC
                 TMKM & tmkm, bool & isBin,
                 const vector<SqlItem> &res)
{
    ANON_REGION(__func__, &perf_cg);

    LOG(crypto) << "crypting data ";

    if (ft==TYPE_INTEGER) {
        LOG(crypto) << data;
    }
    else {
        LOG(crypto) << marshallBinary(data);
    }
    LOG(crypto) << " type " << ft
            << " fullname " << fullname
            << " anonfullname " << anonfullname
            << " fromlevel " << levelnames[(int) fromlevel]
                                           << " tolevel " << levelnames[(int) tolevel]
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

    AES_KEY * mkey;

    if (mp) {
        if (tmkm.processingQuery) {
            string key = mp->get_key(fullname, tmkm);
            //cm->setMasterKey(key);
            mkey = cm->getKey(key);
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
            //cm->setMasterKey(key);
            mkey = cm->getKey(key);
            if (VERBOSE_V) {
                // cerr<<"++> crypting " << anonfullname << " contents " <<
                // data << " fromlevel " << fromlevel;
                // cerr<< " tolevel " << tolevel << " salt " << salt << " key
                // "; myPrint(key, AES_KEY_BYTES);
            }
            //cerr << "++> crypting " << data << " with key "; myPrint(key,
            // AES_KEY_BYTES); cerr << "\n";

        }
    } else {
        mkey = cm->getmkey();
    }

    string resu = cm->crypt(
        mkey, data, ft, anonfullname, fromlevel, tolevel, isBin, salt);
    if (VERBOSE_V) {
        //cerr << "result is " << resu << "\n";
    }
    if (isBin) {
        LOG(crypto) << "result is " << marshallBinary(resu);
    } else {
        LOG(crypto) << "result is " << resu;
    }
    return resu;
}
