/*
 * Translator.h
 *
 *  Created on: Aug 13, 2010
 *      Author: raluca
 *
 *  Logic of translation between unencrypted and encrypted fields and
 *manipulations of fields and tables.
 *
 */

#ifndef Translator_H_
#define Translator_H_

#include "util.h"
#include "CryptoManager.h"
#include <map>
#include <vector>
#include <list>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include "Connect.h"
#include "AccessManager.h"

using namespace std;

/****
 *
 * Layout of tuples is
 *  (random, -- a random number, 8 bytes, bigint
 *   field1VAL -- 4 bytes encryption
 *   field1DET -- 8 bytes encryption
 *   field1OPE -- 8 bytes encryption
 *   field2VAL
 *   field2OPE
 *   ...
 *  )
 */

string getOnionName(FieldMetadata * fm, onion o);

SECLEVEL getLevelForOnion(FieldMetadata * fm, onion o);
SECLEVEL getLevelPlain(onion o);

bool isCommand(string str);

//computes query metadata (e.g. table names, aliases)
QueryMeta getQueryMeta(command c, list<string> query, map<string,
                                                          TableMetadata *> &
                       tableMetaMap)
throw (CryptDBError);

//it is made to point to the first field after select and distinct if they
// exist
string getFieldsItSelect(list<string> & words, list<string>::iterator & it);

bool isNested(const string &query);

//returns the name of a field if field is not encrypted, else it returns the
// DET name
string getFieldName(FieldMetadata * fm);

//returns true if token is of the form 'string.string"
bool isTableField(string token);
string fullName(string field, string name);

bool isTable(string token, const map<string, TableMetadata *> & tm);
bool isField(string token);
//given table.field, the following two return the appropriate part
//if the structure given is not of this form, it is considered a field with ""
// table
string getField(string tablefield);
string getTable(string tablefield);
bool isFieldSalt(string id);

//given a token representing a field, it returns the unanonymized table and
// field; these are original names and ignore aliases
// given token is unanonymized
void getTableField(string token, string & table, string & field,
                   QueryMeta & qm, map<string,
                                       TableMetadata * > & tm)
throw (CryptDBError);

//returns how a field should be called in a select anonymized query
// if table has alias, alias is used instead of anontabless
//if ignoreDecFirst is set to true, the function will behave as if
// DECRYPTFIRST were false
string fieldNameForQuery(string anontable, string table, string anonfield,
                         fieldType ft,  QueryMeta & qm,
                         bool ignoreDecFirst = false);
//returns the name of the given field as it should appear in the query result
// table, field are unanonymized names
//should allow *
//does not consider field aliases
string fieldNameForResponse(string table, string field, string origName,
                            QueryMeta & qm, bool isAgg = false);

string anonFieldNameForDecrypt(FieldMetadata * fm);

//"wordsIt" should point to the token of the aggregate
//if forquery is returned, it returns the entire aggregate expression with
// aliases as it should appear in the query
//if !forquery, it returns the name of this result as it should appear in the
// results
//advances wordsIt after entire expression with aliases
string processAgg(list<string>::iterator & wordsIt, list<string> & words,
                  string & field, string & table, onion & o, QueryMeta & qm,
                  map<string, TableMetadata *> & tm,
                  bool forquery);

string processCreate(fieldType type, string fieldName, unsigned int index,
                     bool encryptField,  TableMetadata * tm,
                     FieldMetadata * fm)
throw (CryptDBError);

//returns what should be included in an insert query for a certain field
string processInsert(string field, string table, TableMetadata *  tm);

//expects it to point to an expression from a where clause
// if this clause contains only sensitive fields, it returns true and it
// remains unchanged
// if this clause contains only insensitive fields or non-field elements, it
// returns false and it points until after
// this expression; in this case res is the value to be included in the query
// the clause cannot be a combination of sensitive and insensitive
//keys indicates which are the keys at which an expression ends
bool processSensitive(list<string>::iterator & it, list<string> & words,
                      string & res, QueryMeta & qm, map<string,
                                                        TableMetadata *> & tm);

// fetches the next auto increment value for fullname and updates autoInc
string nextAutoInc(map<string, unsigned int> & autoInc, string fullname);

//adds in the respective lists queries for which decryption is needed at the
// server
void processDecryptionsForOp(string operation, string op1, string op2,
                             FieldsToDecrypt & fieldsDec, QueryMeta & qm,
                             map<string,
                                 TableMetadata *> & tableMetaMap)
throw (CryptDBError);

/*
   // input: a list of words corresponding to the WHERE clause of a query (all
      data after WHERE)
   // effects/outputs: fieldsDec contains fields to be decrypted, whereClause
      contains the encrypted where clause, tm and fm are also updated
   void processWHERE(list<string> words, TableMetadata * tm, FieldMetadata
      *fm, CryptoManager * cm, FieldsToDecrypt & fieldsDec, string &
      whereClause);
   //
 */

string anonymizeTableName(unsigned int tableNo, string tableName);
string anonymizeFieldName(unsigned int index, onion o, string origname);

#endif /* Translator_H_ */
