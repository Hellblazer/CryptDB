/******************************************************************************
  Functions that will be dynamically loaded by the postgres server.
  -- file structured using the examples from postgres tutorial funcs.*
  -- format:
  DECRYPT( encrypted value  -- if type is integer, this is bigint; if type is text, this is bytea
	   key as a sequence of bytes -- eg. AES_KEY_BYTES no. of bytes; use unmarshall
	   salt  -- eg. bigint
	   )

//can only search for a word
  SEARCH (
           word to be searched -- bytea,
           the value of the field on which we search, bytea

         )


 *****************************************************************************/

#define DEBUG 1

#include "util.h"

extern "C" {


#if MYSQL_S

typedef unsigned long long ulonglong;
typedef long long longlong;
#include <mysql.h>
#include <ctype.h>

#else /* Postgres */

#include "postgres.h"			/* general Postgres declarations */
#include "utils/array.h"
#include "executor/executor.h"	/* for GetAttributeByName() */

#endif

}

#include "../EDB/CryptoManager.h" /* various functions for EDB */


extern "C" {


/* These prototypes just prevent possible warnings from gcc. */
#if MYSQL_S

my_bool decrypt_int_sem_init(UDF_INIT *initid, UDF_ARGS *args,  char *message);
my_bool decrypt_int_det_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)));
my_bool encrypt_int_det_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)));
longlong decrypt_int_sem(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error);
longlong decrypt_int_det(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error);
longlong encrypt_int_det(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error);

//my_bool decrypt_text_sem_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)));
char * decrypt_text_sem(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error __attribute__((unused)));

//my_bool search_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)));
longlong search(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error);

my_bool agg_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)));

//char * agg_init(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error);
char * agg(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error);

//void agg_clear_init(UDF_INIT *initid, char *is_null, char *error);
//char * agg_add_init(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error);
void agg_clear(UDF_INIT *initid, char *is_null, char *error);
my_bool agg_add(UDF_INIT *initid, UDF_ARGS * args, char *is_null, char * error);

my_bool func_add_set_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)));
//char * func_add_set_init(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error);
char * func_add_set(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error);

#else

PG_MODULE_MAGIC;

Datum	decrypt_int_sem(PG_FUNCTION_ARGS);
Datum decrypt_int_det(PG_FUNCTION_ARGS);
Datum decrypt_text_sem(PG_FUNCTION_ARGS);
Datum   search(PG_FUNCTION_ARGS);
Datum  func_add(PG_FUNCTION_ARGS);
Datum  func_add_final(PG_FUNCTION_ARGS);
Datum func_add_set(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(decrypt_int_sem);
PG_FUNCTION_INFO_V1(decrypt_int_det);
PG_FUNCTION_INFO_V1(decrypt_text_sem);
PG_FUNCTION_INFO_V1(search);
PG_FUNCTION_INFO_V1(func_add);
PG_FUNCTION_INFO_V1(func_add_final);
PG_FUNCTION_INFO_V1(func_add_set);

#endif

}

extern "C++" {

void log(string s) {
	s = "echo " + s + " >> /home/raluca/EncryptDB/src/EDB/mylogs ";
	if (system(getCStr(s)) < 0) {exit(-1);}
}

AES_KEY * get_key_SEM(unsigned char * key) {
	return CryptoManager::get_key_SEM(key);
}

AES_KEY * get_key_DET(unsigned char * key) {
	return CryptoManager::get_key_DET(key);
}

uint64_t decrypt_SEM(uint64_t value, AES_KEY * aesKey, uint64_t salt) {
	return CryptoManager::decrypt_SEM(value, aesKey, salt);
}

uint64_t decrypt_DET(uint64_t ciph, AES_KEY* aesKey) {
	return CryptoManager::decrypt_DET(ciph, aesKey);
}


uint64_t encrypt_DET(uint64_t plaintext, AES_KEY * aesKey) {
	return CryptoManager::encrypt_DET(plaintext, aesKey);
}


unsigned char * decrypt_SEM(unsigned char * eValueBytes, unsigned int eValueLen, AES_KEY * aesKey, uint64_t salt) {
	return CryptoManager::decrypt_SEM(eValueBytes, eValueLen, aesKey, salt);
}

}

extern "C" {

#if MYSQL_S

my_bool decrypt_int_sem_init(UDF_INIT *initid, UDF_ARGS *args,  char *message){
	return 0;
}

my_bool decrypt_int_det_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused))) { return 0; }

my_bool encrypt_int_det_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused))) { return 0; }

my_bool decrypt_text_sem_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused))) { return 0; }



my_bool search_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused))) { return 0; }


my_bool func_add_set_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused))) {return 0;}

my_bool agg_init(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args __attribute__((unused)),  char *message __attribute__((unused)))  { return 0; }



	#define ARGS args

	uint64_t getui(UDF_ARGS * args, int i) {
		return (uint64_t) (*((longlong *) args->args[i]));
	}

	unsigned char getb(UDF_ARGS * args, int i) {
		return (unsigned char)(*((longlong *) args->args[i]));
	}
	unsigned char * getba(UDF_ARGS * args, int i, unsigned int & len) {
		len = args->lengths[i];
		return (unsigned char*) (args->args[i]);
	}
	void * myalloc(unsigned int nb) {
		return malloc(nb);
	}

#else

	#define ARGS PG_FUNCTION_ARGS

	uint64_t getui(ARGS, int i) {
		return PG_GETARG_INT64(i);
	}
	unsigned char getb(ARGS, int i) {
		return (unsigned char)PG_GETARG_INT32(i);
	}
	unsigned char * getba(ARGS, int i, unsigned int & len) {
		bytea * eValue = PG_GETARG_BYTEA_P(i);

		len = VARSIZE(eValue) - VARHDRSZ;
		unsigned char * eValueBytes = new unsigned char[len];
		memcpy(eValueBytes, VARDATA(eValue), len);
		return eValueBytes;
	}
	void * myalloc(ARGS, unsigned int nb) {
		return palloc(nb);
	}

#endif

#if MYSQL_S
longlong decrypt_int_sem(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error)
#else /*postgres*/
Datum decrypt_int_sem(PG_FUNCTION_ARGS)
#endif
{

	uint64_t eValue = getui(ARGS, 0);

	unsigned char * key = (unsigned char *) myalloc(AES_KEY_BYTES);
	int offset = 1;

	for (unsigned int i = 0; i < AES_KEY_BYTES; i++) {
		key[i] =  getb(ARGS, offset+i);
	}

	uint64_t salt = getui(args, offset + AES_KEY_BYTES);

	AES_KEY * aesKey = get_key_SEM(key);
	uint64_t value = decrypt_SEM(eValue, aesKey, salt);

#if MYSQL_S
	return (longlong) value;
#else /* postgres */
	PG_RETURN_INT64(value);
#endif


}


#if MYSQL_S
longlong decrypt_int_det(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error)
#else /* postgres */
Datum decrypt_int_det(PG_FUNCTION_ARGS)
#endif
{
	uint64_t eValue = getui(ARGS, 0);

	unsigned char * key = (unsigned char *) myalloc(AES_KEY_BYTES);
	int offset = 1;

	for (unsigned int i = 0; i < AES_KEY_BYTES; i++) {
		key[i] = getb(ARGS, offset+i);
	}

	AES_KEY * aesKey = get_key_DET(key);
	uint64_t value = decrypt_DET(eValue, aesKey);

	free(key);
	free(aesKey);

#if MYSQL_S
	return (longlong) value;
#else /* postgres */
	PG_RETURN_INT64(value);
#endif

}



#if MYSQL_S
longlong encrypt_int_det(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error)
#else /* postgres */
Datum decrypt_int_det(PG_FUNCTION_ARGS)
#endif
{
	uint64_t eValue = getui(ARGS, 0);

	unsigned char * key = (unsigned char *) myalloc(AES_KEY_BYTES);
	int offset = 1;

	for (unsigned int i = 0; i < AES_KEY_BYTES; i++) {
		key[i] = getb(ARGS, offset+i);
	}

	AES_KEY * aesKey = get_key_DET(key);
	uint64_t value = encrypt_DET(eValue, aesKey);

	free(key);
	free(aesKey);

#if MYSQL_S
	return (longlong) value;
#else /* postgres */
	PG_RETURN_INT64(value);
#endif

}


#if MYSQL_S
char * decrypt_text_sem(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error __attribute__((unused)))
#else /* postgres */
Datum decrypt_text_sem(PG_FUNCTION_ARGS)
#endif
{
	unsigned int eValueLen;
	unsigned char * eValueBytes = getba(args, 0, eValueLen);

	unsigned char * key = (unsigned char *) myalloc(AES_KEY_BYTES);
	int offset = 1;

	for (unsigned int i = 0; i < AES_KEY_BYTES; i++) {
		key[i] = getb(ARGS,offset+i);
	}

	uint64_t salt = getui(ARGS, offset + AES_KEY_BYTES);

	AES_KEY * aesKey = get_key_SEM(key);
	unsigned char * value = decrypt_SEM(eValueBytes, eValueLen, aesKey, salt);


	free(key);
	free(aesKey);
	//   string s = marshallBinaryOnce(value, eValueLen);
	//	const char * t = s.c_str();
	//	unsigned int sLen = s.length();

#if MYSQL_S
	*length = eValueLen;
	result = (char *)value;
	//value[eValueLen] = '\0';
	return (char*) value;
#else
	bytea * res = (bytea *) palloc(eValueLen+VARHDRSZ);
	SET_VARSIZE(res, eValueLen+VARHDRSZ);

	memcpy(VARDATA(res), value, eValueLen);

	PG_RETURN_BYTEA_P(res);
#endif

}


// given field of the form:   len1 word1 len2 word2 len3 word3 ..., where each len is the length of the following "word"
// search for word which is of the form len word_body where len is the length of the word body
#if MYSQL_S
longlong search(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error)
#else
Datum search(PG_FUNCTION_ARGS)
#endif
{
	unsigned int wordLen;
	char * word = (char *)getba(ARGS, 0, wordLen);
	if (wordLen != (unsigned int)word[0]) {
		cerr << "ERR: wordLen is not equal to fist byte of word!!! ";
	}
	word = word + 1; // +1 skips over the length field
	//cerr << "given expr to search for has " << wordLen << " length \n";
	unsigned int fieldLen;
	char* field = (char *) getba(ARGS, 1, fieldLen);


	//cerr << "searching for "; myPrint((unsigned char *)word, wordLen); cerr << " in field "; myPrint((unsigned char *)field, fieldLen); cerr << "\n";

	unsigned int i = 0;
	while (i < fieldLen) {
		unsigned int currLen = (unsigned int)field[i];
		if (currLen != wordLen) {
			i = i + currLen+1;
			continue;
		}

		//need to compare
		unsigned int j;
		for (j = 0; j < currLen; j++) {
			if (field[i+j+1] != word[j]) {
				break;
			}
		}
		if (j == currLen) {
#if MYSQL_S
			return 1;
#else
			PG_RETURN_BOOL(true);
#endif
		}
		i = i + currLen + 1;
	}

#if MYSQL_S
			return 0;
#else
			PG_RETURN_BOOL(true);
#endif

}


//this function is called for every row in a group
#if MYSQL_S

//need to initialize the initid value
void agg_clear(UDF_INIT *initid, char *is_null, char *error) {
//	log("inside agg_clear");


	initid->ptr = (char *) myalloc(CryptoManager::Paillier_len_bytes);
	memcpy(initid->ptr, BytesFromZZ(to_ZZ(1), CryptoManager::Paillier_len_bytes), CryptoManager::Paillier_len_bytes);
}

//args will be element to add, constant N2
my_bool agg_add(UDF_INIT *initid, UDF_ARGS * args, char * is_null, char * error) {

	//log("inside agg_add");
	unsigned char * bytesA = (unsigned char *)initid->ptr;//passed through iterations
	unsigned int lenB, lenN2;
	unsigned char * bytesB = getba(args, 0, lenB);
	unsigned char * bytesN2 = getba(args, 1, lenN2); //TODO: if N2 is hardcoded, it can be faster


	if (lenB != lenN2) {
		cerr << "error: lenB != lenN2 \n";
		cerr << "lenB is " << lenB << " lenN2 is " << lenN2 << "\n";
		return false;
	}

	//cerr << "lenB is " << lenB << "\n";
    //cerr << "a is " ; myPrint(bytesA, 10); cerr << "\n";
    //cerr << "b is " ; myPrint(bytesB, 10); cerr << "\n";
    //cerr << "n2 is "; myPrint(bytesN2, 10); cerr << "\n";

	unsigned char * bytesRes = homomorphicAdd(bytesA, bytesB, bytesN2, lenN2);

	initid->ptr = (char *)bytesRes;

	return true;

}
#else
Datum func_add(PG_FUNCTION_ARGS) {


	int lenN2, lenB;
	unsigned char * bytesN2;
	unsigned char * bytesA;
	unsigned char * bytesB;

	bytea * input = PG_GETARG_BYTEA_P(0);
	lenN2 = (VARSIZE(input)- VARHDRSZ)/2;
	//cerr << "lenN2 " << lenN2 << "\n";
	bytesA = (unsigned char *)VARDATA(input);
	bytesN2 = bytesA+lenN2;


	bytea * inputB = PG_GETARG_BYTEA_P(1);
	lenB = VARSIZE(inputB) - VARHDRSZ;
	//cerr << "lenB " << lenB << "\n";
	bytesB = (unsigned char *)VARDATA(inputB);

	if (lenB != lenN2) {
		cerr << "error: lenB != lenN2 \n";
		cerr << "lenB is " << lenB << " lenN2 is " << lenN2 << "\n";
		PG_RETURN_BYTEA_P(NULL);
	}

	if (DEBUG) {myPrint(bytesA, lenN2);}


	unsigned char * bytesRes = homomorphicAdd(bytesA, bytesB, bytesN2, lenN2);

	//cerr << "product "; myPrint(bytesRes, lenN2); cerr << " ";


	memcpy(VARDATA(input), bytesRes, lenN2);

	PG_RETURN_BYTEA_P(input);
}
#endif





#if MYSQL_S
 //should return value from the init variable
char * agg(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error) {

	//cerr << "in AGG!!!!\n";fflush(stderr);
	result = initid->ptr;
	*length = CryptoManager::Paillier_len_bytes;
	//cerr << "done with agg, just returning\n";
	return result;
}
#else
Datum func_add_final(PG_FUNCTION_ARGS) {


	bytea  * input = PG_GETARG_BYTEA_P(0);

	int lenN2 = (VARSIZE(input) - VARHDRSZ) / 2;

	bytea * res = (bytea *) palloc(lenN2 + VARHDRSZ);


	SET_VARSIZE(res, lenN2+VARHDRSZ);
	memcpy(VARDATA(res), VARDATA(input), lenN2);

	PG_RETURN_BYTEA_P(res);
}
#endif

#if MYSQL_S
char * func_add_set(UDF_INIT *initid, UDF_ARGS * args, char *result, unsigned long *length, char * is_null, char * error){
#else
//for update with increment
Datum func_add_set(PG_FUNCTION_ARGS) {
#endif
	unsigned char * val;
	unsigned char * N2;
	unsigned char * field;
	unsigned int valLen, fieldLen, N2Len;

	field = getba(ARGS, 0, fieldLen);
	val = getba(ARGS, 1, valLen);
	N2 = getba(ARGS, 2, N2Len);

	myassert(fieldLen == N2Len, "length of the field differs from N2 len");
	myassert(valLen == N2Len, "length of val differs from N2 len");

	unsigned char * res = homomorphicAdd(field, val, N2, N2Len);

#if MYSQL_S
	result = (char *)res;
	*length = N2Len;
	return result;
#else
	bytea * resBytea = (bytea *) palloc(N2Len + VARHDRSZ);

	SET_VARSIZE(resBytea, N2Len + VARHDRSZ);
	memcpy(VARDATA(resBytea), res, N2Len);

	PG_RETURN_BYTEA_P(resBytea);

#endif

}



}
