#pragma once

/*
 * Translator.h
 *
 *  Created on: Aug 13, 2010
 *      Author: raluca
 *
 * Logic of translation between unencrypted and encrypted fields and
 * manipulations of fields and tables.
 */

#include <map>
#include <vector>
#include <list>
#include <string>
#include <stdio.h>
#include <stdlib.h>

#include <edb/Connect.hh>
#include <edb/AccessManager.hh>
#include <crypto-old/CryptoManager.hh>


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

std::string getOnionName(FieldMetadata * fm, onion o);

SECLEVEL getLevelForOnion(FieldMetadata * fm, onion o);
SECLEVEL getLevelPlain(onion o);


bool isCommand(std::string str);

//computes query metadata (e.g. table names, aliases)
QueryMeta getQueryMeta(command c, std::list<std::string> query, std::map<std::string,
                                                          TableMetadata *> &
                       tableMetaMap)
    throw (CryptDBError);

//it is made to point to the first field after select and distinct if they
// exist
std::string getFieldsItSelect(std::list<std::string> & words, std::list<std::string>::iterator & it);

bool isNested(const std::string &query);

//returns the name of a field if field is not encrypted, else it returns the
// DET name
std::string getFieldName(FieldMetadata * fm);

//returns true if token is of the form 'string.string"
bool isTableField(std::string token);
std::string fullName(std::string field, std::string name);

bool isTable(std::string token, const std::map<std::string, TableMetadata *> & tm);
bool isField(std::string token);
//given table.field, the following two return the appropriate part
//if the structure given is not of this form, it is considered a field with ""
// table
std::string getField(std::string tablefield);
std::string getTable(std::string tablefield);

//returns the name of the salt for a field with index in the table
std::string getFieldSalt(unsigned int index, std::string anontablename);
//returns true if "id" is the name of salt; isTableSalt set to true  if it is
std::string
getTableSalt(std::string anonTableName);
// a table salt
bool isSalt(std::string id, bool & isTableSalt);
//returns the anonymized name of the table with this salt
std::string getTableOfSalt(std::string salt_name);


//given a token representing a field, it returns the unanonymized table and
// field; these are original names and ignore aliases
// given token is unanonymized
void getTableField(std::string token, std::string & table, std::string & field,
                   QueryMeta & qm, std::map<std::string,
                                       TableMetadata * > & tm)
    throw (CryptDBError);

//returns how a field should be called in a select anonymized query
// if table has alias, alias is used instead of anontabless
//if ignoreDecFirst is set to true, the function will behave as if
// DECRYPTFIRST were false
std::string fieldNameForQuery(std::string anontable, std::string table, std::string anonfield,
                         const FieldMetadata * fm,  QueryMeta & qm,
                         bool ignoreDecFirst = false);
//returns the name of the given field as it should appear in the query result
// table, field are unanonymized names
//should allow *
//does not consider field aliases
std::string fieldNameForResponse(std::string table, std::string field, std::string origName,
                            QueryMeta & qm, bool isAgg = false);

std::string anonFieldNameForDecrypt(FieldMetadata * fm);

//"wordsIt" should point to the token of the aggregate
//if forquery is returned, it returns the entire aggregate expression with
// aliases as it should appear in the query
//if !forquery, it returns the name of this result as it should appear in the
// results
//advances wordsIt after entire expression with aliases
std::string processAgg(std::list<std::string>::iterator & wordsIt, std::list<std::string> & words,
                  std::string & field, std::string & table, onion & o, QueryMeta & qm,
                  std::map<std::string, TableMetadata *> & tm,
                  bool forquery);

std::string processCreate(fieldType type, std::string fieldName, unsigned int index,
                     TableMetadata * tm, FieldMetadata * fm, bool multiPrinc)
    throw (CryptDBError);

//returns what should be included in an insert query for a certain field
std::string processInsert(std::string field, std::string table, FieldMetadata * fm, TableMetadata *  tm);

//expects it to point to an expression from a where clause
// if this clause contains only sensitive fields, it returns true and it
// remains unchanged
// if this clause contains only insensitive fields or non-field elements, it
// returns false and it points until after
// this expression; in this case res is the value to be included in the query
// the clause cannot be a combination of sensitive and insensitive
//keys indicates which are the keys at which an expression ends
bool processSensitive(std::list<std::string>::iterator & it, std::list<std::string> & words,
                      std::string & res, QueryMeta & qm, std::map<std::string,
                                                        TableMetadata *> & tm);

// fetches the next auto increment value for fullname and updates autoInc
std::string nextAutoInc(std::map<std::string, unsigned int> & autoInc, std::string fullname);

//adds in the respective lists queries for which decryption is needed at the
// server
void processDecryptionsForOp(std::string operation, std::string op1, std::string op2,
                             FieldsToDecrypt & fieldsDec, QueryMeta & qm,
                             std::map<std::string,
                                 TableMetadata *> & tableMetaMap)
    throw (CryptDBError);

/*
   // input: a list of words corresponding to the WHERE clause of a query (all
      data after WHERE)
   // effects/outputs: fieldsDec contains fields to be decrypted, whereClause
      contains the encrypted where clause, tm and fm are also updated
   void processWHERE(std::list<std::string> words, TableMetadata * tm, FieldMetadata
   *fm, CryptoManager * cm, FieldsToDecrypt & fieldsDec, std::string &
      whereClause);
   //
 */

std::string anonymizeTableName(unsigned int tableNo, std::string tableName, bool multiPrinc);
std::string anonymizeFieldName(unsigned int index, onion o, std::string origname, bool multiPrinc);
