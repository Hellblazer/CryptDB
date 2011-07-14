#ifndef _UTIL_H
#define _UTIL_H

/*
 * util.h
 *
 * A set of useful constants, data structures and functions.
 */


#include <stdlib.h>
#include <stdio.h>
#include <string>
#include "string.h"
#include <list>
#include <map>
#include "stdint.h"
#include <sys/time.h>
#include "params.h"
#include <vector>
#include <set>
#include "Equation.h"

#include "NTL/ZZ.h"
using namespace NTL;

using namespace std;



// ==== CONSTANTS ============== //

#define PAILLIER_LEN_BYTES 256
#define PAILLIER_LEN_BYTES_C "256"

#if MYSQL_S
#define TN_I32 "integer"
#define TN_I64 "bigint"
#define TN_TEXT "blob"
#define TN_HOM "varbinary("PAILLIER_LEN_BYTES_C")"
#define TN_PTEXT "text"
#else
#define TN_I32 "integer"
#define TN_I64 "bigint"
#define TN_TEXT "BYTEA"
#define TN_HOM "BYTEA("PAILLIER_LEN_BYTES_C")"
#define TN_PTEXT "text"
#endif

#define TN_SYM_KEY "varbinary(16)"
#define TN_PK_KEY  "varbinary(1200)"


// configuration for debugging, testing
#define ANONTABLES (1-MULTIPRINC)  //whether to anonymize tables names
#define ANONDETFIELD (1-MULTIPRINC) //whether to anonymize the det field


#define psswdtable "activeusers"

const unsigned int bitsPerByte = 8;
const unsigned int bytesPerInt = 4;

const uint32_t MAX_UINT32_T = - 1;
const uint64_t MAX_UINT64_T = - 1;

const unsigned int AES_BLOCK_BITS = 128;
const unsigned int AES_BLOCK_BYTES = AES_BLOCK_BITS/bitsPerByte;
const unsigned int AES_KEY_SIZE = 128;
const unsigned int AES_KEY_BYTES = AES_KEY_SIZE/bitsPerByte;

const unsigned int MASTER_KEY_SIZE = AES_KEY_SIZE; //master key

const unsigned int OPE_KEY_SIZE = AES_KEY_SIZE;
const unsigned int OPE_PLAINTEXT_SIZE = 32;
const unsigned int OPE_CIPHERTEXT_SIZE = 64;

const unsigned int EncryptedIntSize = 128;

const unsigned int bytesOfTextForOPE = 20; //texts may be ordered alphabetically -- this variable indicates how many of the first bytes should be used for sorting

// text supports search only on words separated by these separators
const string wordSeparators = "; .,'-{}()";

const string dec_first_key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x01\x02\x03\x04\x05\x06";
const string PWD_TABLE_PREFIX = "pwdcryptdb__";


// ============= DATA STRUCTURES ===================================//

typedef vector<vector<string> > ResType;

#if MYSQL_S
	#include "mysql.h"
	typedef MYSQL_RES DBResult_native;
#else
	#include "libpq-fe.h"
	typedef PGresult DBResult_native;
#endif

typedef struct SyntaxError {
	string msg;
} SyntaxError;


typedef enum fieldType {TYPE_TEXT, TYPE_INTEGER, TYPE_AGG_RESULT_COUNT, TYPE_AGG_RESULT_SUM, TYPE_AGG_RESULT_SET, TYPE_OPE} fieldType;
typedef enum onion {oDET, oOPE, oAGG, oNONE, oINVALID} onion;

typedef struct AutoInc {
	long incvalue;
} AutoInc;


typedef struct ParserMeta {
	std::set<string> clauseKeywords_p;
	std::set<string> querySeparators_p;
	ParserMeta();
} ParserMeta;

typedef enum SECLEVEL      {INVALID,   PLAIN,  PLAIN_DET,  DETJOIN,  DET,  SEMANTIC_DET, PLAIN_OPE, OPEJOIN, OPESELF, SEMANTIC_OPE, PLAIN_AGG, SEMANTIC_AGG, SEMANTIC_VAL} SECLEVEL;

const string levelnames[] ={"invalid","plain","plaindet", "detjoin","det","semanticdet", "plainope", "opejoin","ope", "semope", "plainagg", "semmagg", "semval"};

typedef enum command {CREATE, UPDATE, INSERT, SELECT, DROP, DELETE, BEGIN, COMMIT, ALTER, OTHER} command;

typedef struct FieldMetadata {

	bool isEncrypted; //indicates if this field is encrypted or not

	fieldType type;
	string fieldName;

	string anonFieldNameDET;
	string anonFieldNameOPE;
	string anonFieldNameAGG;

	FieldMetadata();

	enum SECLEVEL secLevelOPE, secLevelDET;

	bool INCREMENT_HAPPENED;

	//for training purposes
	bool ope_used;
	bool agg_used;

	//returns true if the given field exists in the database
	static bool exists(string field);

} FieldMetadata;

typedef struct IndexMetadata{
	string anonIndexName;
	list<string> fields;
	bool isUnique;
} IndexMetadata;


typedef struct TableMetadata { //each anonymized field
	list<string> fieldNames; //in order field names
	unsigned int tableNo;
	string anonTableName;
	map<string, string> fieldNameMap; //map of anonymized field name to true field name
	map<string, FieldMetadata *> fieldMetaMap; //map of true field name to field metadata

	string autoIncField; //name of field that has autoincrement

	list<string> primaryKey;
	list<IndexMetadata *> indexes;
	bool hasEncrypted; //true if the table contains an encrypted field

} TableMetadata;


typedef struct FieldsToDecrypt {
	list<string> OPEJoinFields;
	list<string> OPEFields;
	list<string> DETFields;
	list<string> DETJoinFields;
} FieldsToDecrypt;

class Operation {
public:
	static bool isOp(string op);
	static bool isDET(string op);
	static bool isOPE(string op);
	static bool isILIKE(string op);
	static bool isIN(string op);

private:


};

typedef struct QueryMeta {
	map<string, string> tabToAlias, aliasToTab;
	list<string> tables;
	map<string, string> aliasToField;

	void cleanup();
} QueryMeta;

typedef struct ResMeta {

	unsigned int nFields, nTuples, nTrueFields;

	/* Indexes in the following vectors correspond to entries in the raw response from the DBMS */

	bool * isSalt; //isSalt[i] = true if i-th entry is salt

	string * table; //real table of each field
	string * field; //real name of each field
	onion * o; //onion of each field

	string * namesForRes; //this is the name of the field to be included in result -- considering aliases -- for aggregates, use field inside

	void cleanup();

} ResMeta;


typedef struct Result {
	vector<vector<string> > a;
} Result;


typedef struct Predicate {
	string name;
	list<string> fields;
} Predicate;

/********* Data structures for multi-key CryptDB -- should not be used by single-principal ****/

//permanent metadata for multi-key CryptDB - stores which field is encrypted for which field
typedef struct MultiKeyMeta {
	//e.g., msg_text encrypted for principal u.id
	map<string, string> encForMap;
	//contains an element if that element has some field encrypted to it
	map<string, bool > reverseEncFor;
	map<string, Predicate *> condAccess; //maps a field having accessto to any conditional predicate it may have

	void cleanup();
} MKM;

//temporary metadata for multi-key CryptDB that belongs to the query or result being processed
typedef struct TempMKM {
	//maps a field (fullname) that has another field encrypted for it to its value
	// groups.gid    23
	map<string, string> encForVal;

	//maps a field that has another field encrypted for it to the index in the response list of values containing its value
	// groups.gid 5
	map<string, int> encForReturned;

	// contains fullnames of principals that were seen already in a response
	map<string, bool> principalsSeen;

	//true if current processing is query rather
	bool processingQuery;

	//some fields will be selected in order to be able to decrypt others, but should not
	// be returned in the response to the application
	// maps position in raw DBMS response to whether it should be returned to user or not
	map<unsigned int, bool> returnBitMap;

	void cleanup();

} TMKM;

//=============  Useful functions =========================//



// extracts (nobytes) bytes from int by placing the most significant bits at the end
string BytesFromInt(uint64_t value, unsigned int noBytes);
uint64_t IntFromBytes(const unsigned char * bytes, unsigned int noBytes);

void assert_s (bool value, string msg) throw (SyntaxError);
void myassert(bool value, const char * mess);
void myassert(bool value, string mess);


double timeInSec(struct timeval tvstart, struct timeval tvend);
double timeInMSec(struct timeval tvstart, struct timeval tvend);

//parsing
const char delimsStay[5] = {'(', ')', '=', ',' , '\0'};
const char delimsGo[5] = {';', ' ', '\t', '\n', '\0'};
const char keepIntact[2] ={'\'', '\0'};


bool isKeyword(string token);

const unsigned int noCommands = 9;
const string commands[] = {"select", "create", "insert", "update", "delete", "drop", "alter"};

const unsigned int noAggregates = 4;
const string aggregates[] = {"max", "min", "sum", "count"};
bool isAgg(string token);

const unsigned int noCreateMeta = 3;
const string createMetaKeywords[] = {"primary", "key", "unique"};

const unsigned int noComps = 3;
const string comparisons[] ={">", "<", "="};
const unsigned int noMath = 17;
const string math[]={"+","-","(",")","*","/",".","0","1","2","3","4","5","6","7","8","9"};

const ParserMeta parserMeta = ParserMeta();

void myassert(bool value);

//transforms a string in a char *, where char * is a properly-allocated pointer
char * getCStr(string value);


const char * removeString(const char * input, string toremove);

//returns a list that consists of lst1 and lst2 concatenated in this order
list<string> concatenate(const list<string> & lst1, const list<string>  & lst2);

//appends the contents of lst2 to lst1
void append(list<string> & lst1, const list<string> & lst2);

string randomBytes(unsigned int len);
uint64_t randomValue();

void myPrint(const unsigned char * a, unsigned int aLen);
void myPrint(const char * a);
void myPrint(const list<string> & lst);
void myPrint(list<const char *> & lst);
void myPrint(const vector<string> & vec);
void myPrint(const vector<vector<string> > & d);
void myPrint(vector<bool> & bitmap);
void myPrint(const unsigned int * a, unsigned int aLen);
void myPrint(const string &s);

string toString(const list<string> & lst);
string toString(const vector<bool> & vec);
string toString(const std::set<string> & lst);
string toString(const ResType & rt);
string toString(unsigned char * key, unsigned int len);

bool isEqual(unsigned char * first, unsigned char * second, unsigned int len);


// tries to represent value in minimum no of bytes, avoiding the \0 character
string StringFromVal(unsigned int value, unsigned int desiredLen);
//returns a string that is value
string StringFromVal(unsigned long value);

ZZ UInt64_tToZZ (uint64_t value);

// a const char looking like "123" becomes an unsigned char with value 123
unsigned char ByteFromCharA(const char * a);


unsigned char * copyInto(unsigned char * res, unsigned char * data, unsigned int pos, unsigned int len);

unsigned char* BytesFromZZ(const ZZ & x, unsigned int noBytes);
string StringFromZZ(const ZZ &x);
ZZ ZZFromString(const string &s);

string uCharToStringDirect(unsigned char * input, unsigned int len);


/***** ITERATORS *******************/
//too bad templates need headers and def to be in same place..
//rolls an interator forward
//template<typename T>
//void roll(typename list<T>::iterator & it,  int count);
//template<typename T>
//bool isLastIterator(typename list<T>::iterator it, typename list<T>::iterator endit);

//rolls an interator forward
template<typename T> void roll(typename list<T>::iterator & it,  int count) {
	if (count < 0) {
		for (int i = 0; i < -count; i++) {
			it--;
		}
	}
	else {
		for (int i = 0; i < count; i++) {
			it++;
		}
	}
}

template <typename T>
bool isLastIterator(typename list<T>::iterator it, typename list<T>::iterator endit) {
	roll<T>(it, 1);
	if (it == endit) {
		return true;
	} else {
		return false;
	}
}

list<string> makeList(string val1, string val2);
list<int> makeList(int val1, int val2);

//returns a Postgres bigint representation in string form for x
string marshallVal(uint64_t x);
string marshallVal(uint32_t x);
//returns x written on digits, with most significant first
//if x needs more space than digits, the exact value of x will be returned
string marshallVal(unsigned int x, unsigned int digits);

uint64_t unmarshallVal(string str); 

//marshalls a binary value into characters readable by Postgres 
string marshallBinary(const string &s);
string secondMarshallBinary(unsigned char * binValue, unsigned int len);
// unmarshalls a char * received from Postgres into a binary and
// sets newlen to the length of the result..
// marshall and unmarshallBinary are not inverses of each other.
// XXX why not?
string unmarshallBinary(const string &s);

void consolidate(list<string> & words);

string marshallBinaryOnce(unsigned char * binValue, unsigned int len);

char * copy(const char * v);
unsigned char * copy(unsigned char * v, unsigned int len);


/********* SQL QUERY PARSING ******/

// splits query in a list of string tokens; the tokens are obtained by splitting query at every character contained in delimsStay or delimsGo; the tokens will include the characters
// from delimsStay encountered
list<string> getSQLWords(const char * query);

//parses a given string str, by splitting it according to the delimiters in delimsStay, delimsGo ; if a piece of string
// is included in two keepIntact delimiters, it is not broken into pieces even if this string
//contains delimiters; delimsStay are kept in the result, delimsGo are discarded
list<string> parse(const char * str, const char * delimsStay, const char * delimsGo, const char * keepIntact);

command getCommand(const char * queryI) throw (SyntaxError);

//returns a string representing a value pointed to by it and advances it
string getVal(list<string>::iterator & it);

//checks that the value of the current iterator is s1 or s2;  if it is s1, increment iterator and return s1, if it is s2, return ""; else throws exception
string checkStr(list<string>::iterator & it, list<string> & lst, string s1, string s2);


//acts only if the first field is "(";
//returns position after matching ")" mirroring all contents
string processParen(list<string>::iterator & it, list<string> & words);

bool isQuerySeparator(string st);

//returns the alias that should be pointed by it or "" if there is no such alias
string getAlias(list<string>::iterator & it, list<string> & words);

// "it" should point to item after a field
//echos any aliases, commas or )  in the result,
//advances it after any set of  comma or ),  stops on query separator, or end of query, whichever comes first
//also enforces that there is at most one alias
string processAlias(list<string>::iterator & it, list<string> & words);


//echoes in output all tokens pointed to by it up to when any of the terminators are encountered or it reached end of words
//it mirrors the terminator as well if encountered
//ignores query separators
//if stopAfterTerm, it leaves "it" pointing to first element after terminator, else it points to terminator
//if skipParentBlock, it looks for terminators only outside of any nested parenthesis block
string mirrorUntilTerm(list<string>::iterator & it, list<string> & words, string  terminator[],  unsigned int noTerms, bool stopAfterTerm = 1, bool skipParenBlock = 0);
string mirrorUntilTerm(list<string>::iterator & it, list<string> & words, const std::set<string> & terms, bool stopAfterTerm = 1, bool skipParenBlock = 0);

//returns the iterator that points at the first keyword in lst, or the end of the lst if such keyword was not found
list<string>::iterator itAtKeyword(list<string> & lst, string keyword);

//returns the contents of str before the first encounter with c
string getBeforeChar(string str, char c);




bool contains(string token, list<string> & values);
//performs a case insensitive search
bool contains(string token, const string *  values, unsigned int noValues);

//performs a case insensitive search
bool isOnly(string token, const string * values, unsigned int noValues);

void addIfNotContained(string token, list<string> & lst);
void addIfNotContained(string token1, string token2, list<pair<string, string> > & lst);

string removeApostrophe(string data);
bool hasApostrophe(string data);

string homomorphicAdd(const string &val1, const string &val2, const string &valN2);

string toLowerCase(string token);

bool equalsIgnoreCase(string s1, string s2);


void keywordsToLowerCase(list<string> & lst, ParserMeta * pm);


#endif   /* _UTIL_H */
