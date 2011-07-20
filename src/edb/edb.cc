/*
 * There are three or four incompatible memory allocators:
 *
 *   palloc / pfree (Postgres-specific)
 *   malloc / free
 *   new / delete
 *   new[] / delete[]
 *
 * The Postgres versions of the UDFs likely do not keep track of which
 * allocator is used in each case.  They might not free memory at all
 * in some cases, and might free memory with a different allocator than
 * the one used to initially allocate it.  Beware.
 *
 * The MySQL versions of the UDFs are more likely to get this right.
 */

#define DEBUG 1

#include "util.h"
#include "CryptoManager.h" /* various functions for EDB */

extern "C" {
#if MYSQL_S

typedef unsigned long long ulonglong;
typedef long long longlong;
#include <mysql.h>
#include <ctype.h>

my_bool  decrypt_int_sem_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
longlong decrypt_int_sem(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                         char *error);

my_bool  decrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
longlong decrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                         char *error);

my_bool  decrypt_text_sem_init(UDF_INIT *initid, UDF_ARGS *args,
                               char *message);
void     decrypt_text_sem_deinit(UDF_INIT *initid);
char *   decrypt_text_sem(UDF_INIT *initid, UDF_ARGS *args, char *result,
                          unsigned long *length, char *is_null, char *error);

my_bool  encrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
longlong encrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null,
                         char *error);

my_bool  decrypt_text_det_init(UDF_INIT *initid, UDF_ARGS *args,
                               char *message);
void     decrypt_text_det_deinit(UDF_INIT *initid);
char *   decrypt_text_det(UDF_INIT *initid, UDF_ARGS *args, char *result,
                          unsigned long *length, char *is_null, char *error);

my_bool  search_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
longlong search(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);

my_bool  agg_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void     agg_deinit(UDF_INIT *initid);
void     agg_clear(UDF_INIT *initid, char *is_null, char *error);
my_bool  agg_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);
char *   agg(UDF_INIT *initid, UDF_ARGS *args, char *result,
             unsigned long *length, char *is_null, char *error);

void     func_add_set_deinit(UDF_INIT *initid);
char *   func_add_set(UDF_INIT *initid, UDF_ARGS *args, char *result,
                      unsigned long *length, char *is_null, char *error);


my_bool searchSWP_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void searchSWP_deinit(UDF_INIT *initid);
my_bool searchSWP(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);

#else /* Postgres */

#include "postgres.h"                   /* general Postgres declarations */
#include "utils/array.h"
#include "executor/executor.h"  /* for GetAttributeByName() */

PG_MODULE_MAGIC;

Datum decrypt_int_sem(PG_FUNCTION_ARGS);
Datum decrypt_int_det(PG_FUNCTION_ARGS);
Datum decrypt_text_sem(PG_FUNCTION_ARGS);
Datum decrypt_text_det(PG_FUNCTION_ARGS);
Datum search(PG_FUNCTION_ARGS);
Datum func_add(PG_FUNCTION_ARGS);
Datum func_add_final(PG_FUNCTION_ARGS);
Datum func_add_set(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(decrypt_int_sem);
PG_FUNCTION_INFO_V1(decrypt_int_det);
PG_FUNCTION_INFO_V1(decrypt_text_sem);
PG_FUNCTION_INFO_V1(decrypt_text_det);
PG_FUNCTION_INFO_V1(search);
PG_FUNCTION_INFO_V1(func_add);
PG_FUNCTION_INFO_V1(func_add_final);
PG_FUNCTION_INFO_V1(func_add_set);

#endif
}

static void __attribute__((unused))
log(string s)
{
    /* Writes to the server's error log */
    fprintf(stderr, "%s\n", s.c_str());
}

static AES_KEY *
get_key_SEM(const string &key)
{
    return CryptoManager::get_key_SEM(key);
}

static AES_KEY *
get_key_DET(const string &key)
{
    return CryptoManager::get_key_DET(key);
}

static uint64_t
decrypt_SEM(uint64_t value, AES_KEY * aesKey, uint64_t salt)
{
    return CryptoManager::decrypt_SEM(value, aesKey, salt);
}

static uint64_t
decrypt_DET(uint64_t ciph, AES_KEY* aesKey)
{
    return CryptoManager::decrypt_DET(ciph, aesKey);
}

static uint64_t
encrypt_DET(uint64_t plaintext, AES_KEY * aesKey)
{
    return CryptoManager::encrypt_DET(plaintext, aesKey);
}

static string
decrypt_SEM(unsigned char *eValueBytes, uint64_t eValueLen,
            AES_KEY * aesKey, uint64_t salt)
{
    string c((char *) eValueBytes, (unsigned int) eValueLen);
    return CryptoManager::decrypt_SEM(c, aesKey, salt);
}

static string
decrypt_DET(unsigned char *eValueBytes, uint64_t eValueLen, AES_KEY * key)
{
    string c((char *) eValueBytes, (unsigned int) eValueLen);
    return CryptoManager::decrypt_DET(c, key);
}

static bool
search(const Token & token, const Binary & overall_ciph) {
	return CryptoManager::searchExists(token, overall_ciph);
}

#if MYSQL_S
#define ARGS args

static uint64_t
getui(UDF_ARGS * args, int i)
{
    return (uint64_t) (*((longlong *) args->args[i]));
}

static unsigned char
getb(UDF_ARGS * args, int i)
{
    return (unsigned char)(*((longlong *) args->args[i]));
}

static unsigned char *
getba(UDF_ARGS * args, int i, uint64_t &len)
{
    len = args->lengths[i];
    return (unsigned char*) (args->args[i]);
}

#else

#define ARGS PG_FUNCTION_ARGS

static uint64_t
getui(ARGS, int i)
{
    return PG_GETARG_INT64(i);
}

static unsigned char
getb(ARGS, int i)
{
    return (unsigned char)PG_GETARG_INT32(i);
}

static unsigned char *
getba(ARGS, int i, unsigned int & len)
{
    bytea * eValue = PG_GETARG_BYTEA_P(i);

    len = VARSIZE(eValue) - VARHDRSZ;
    unsigned char * eValueBytes = new unsigned char[len];
    memcpy(eValueBytes, VARDATA(eValue), len);
    return eValueBytes;
}

#endif

extern "C" {

#if MYSQL_S
my_bool
decrypt_int_sem_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

longlong
decrypt_int_sem(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else /*postgres*/
Datum
decrypt_int_sem(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValue = getui(ARGS, 0);

    string key;
    key.resize(AES_KEY_BYTES);
    int offset = 1;

    for (unsigned int i = 0; i < AES_KEY_BYTES; i++)
        key[i] = getb(ARGS, offset+i);

    uint64_t salt = getui(args, offset + AES_KEY_BYTES);

    AES_KEY *aesKey = get_key_SEM(key);
    uint64_t value = decrypt_SEM(eValue, aesKey, salt);
    delete aesKey;

#if MYSQL_S
    return (longlong) value;
#else /* postgres */
    PG_RETURN_INT64(value);
#endif
}

#if MYSQL_S
my_bool
decrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

longlong
decrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else /* postgres */
Datum
decrypt_int_det(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValue = getui(ARGS, 0);

    string key;
    key.resize(AES_KEY_BYTES);
    int offset = 1;

    for (unsigned int i = 0; i < AES_KEY_BYTES; i++)
        key[i] = getb(ARGS, offset+i);

    AES_KEY *aesKey = get_key_DET(key);
    uint64_t value = decrypt_DET(eValue, aesKey);
    delete aesKey;

#if MYSQL_S
    return (longlong) value;
#else /* postgres */
    PG_RETURN_INT64(value);
#endif

}

#if MYSQL_S
my_bool
encrypt_int_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

longlong
encrypt_int_det(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else /* postgres */
Datum
decrypt_int_det(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValue = getui(ARGS, 0);

    string key;
    key.resize(AES_KEY_BYTES);
    int offset = 1;

    for (unsigned int i = 0; i < AES_KEY_BYTES; i++)
        key[i] = getb(ARGS, offset+i);

    AES_KEY *aesKey = get_key_DET(key);
    uint64_t value = encrypt_DET(eValue, aesKey);
    delete aesKey;

#if MYSQL_S
    return (longlong) value;
#else /* postgres */
    PG_RETURN_INT64(value);
#endif

}

#if MYSQL_S
my_bool
decrypt_text_sem_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

void
decrypt_text_sem_deinit(UDF_INIT *initid)
{
    /*
     * in mysql-server/sql/item_func.cc, udf_handler::fix_fields
     * initializes initid.ptr=0 for us.
     */
    if (initid->ptr)
        delete initid->ptr;
}

char *
decrypt_text_sem(UDF_INIT *initid, UDF_ARGS *args,
                 char *result, unsigned long *length,
                 char *is_null, char *error)
#else /* postgres */
Datum
decrypt_text_sem(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValueLen;
    unsigned char *eValueBytes = getba(args, 0, eValueLen);

    string key;
    key.resize(AES_KEY_BYTES);
    int offset = 1;

    for (unsigned int i = 0; i < AES_KEY_BYTES; i++)
        key[i] = getb(ARGS,offset+i);

    uint64_t salt = getui(ARGS, offset + AES_KEY_BYTES);

    AES_KEY *aesKey = get_key_SEM(key);
    string value = decrypt_SEM(eValueBytes, eValueLen, aesKey, salt);
    delete aesKey;

#if MYSQL_S
    initid->ptr = strdup(value.c_str());
    *length = value.length();
    return (char*) initid->ptr;
#else
    bytea * res = (bytea *) palloc(eValueLen+VARHDRSZ);
    SET_VARSIZE(res, eValueLen+VARHDRSZ);
    memcpy(VARDATA(res), value, eValueLen);
    PG_RETURN_BYTEA_P(res);
#endif

}

#if MYSQL_S
my_bool
decrypt_text_det_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

void
decrypt_text_det_deinit(UDF_INIT *initid)
{
    /*
     * in mysql-server/sql/item_func.cc, udf_handler::fix_fields
     * initializes initid.ptr=0 for us.
     */
    if (initid->ptr)
        delete initid->ptr;
}

char *
decrypt_text_det(UDF_INIT *initid, UDF_ARGS *args,
                 char *result, unsigned long *length,
                 char *is_null, char *error)
#else /* postgres */
Datum
decrypt_text_det(PG_FUNCTION_ARGS)
#endif
{
    uint64_t eValueLen;
    unsigned char *eValueBytes = getba(args, 0, eValueLen);

    string key;
    key.resize(AES_KEY_BYTES);
    int offset = 1;

    for (unsigned int i = 0; i < AES_KEY_BYTES; i++) {
        key[i] = getb(ARGS,offset+i);
    }

    AES_KEY *aesKey = get_key_DET(key);
    string value = decrypt_DET(eValueBytes, eValueLen, aesKey);
    delete aesKey;

#if MYSQL_S
    initid->ptr = strdup(value.c_str());
    *length = value.length();
    return (char*) initid->ptr;
#else
    bytea * res = (bytea *) palloc(eValueLen+VARHDRSZ);
    SET_VARSIZE(res, eValueLen+VARHDRSZ);
    memcpy(VARDATA(res), value, eValueLen);
    PG_RETURN_BYTEA_P(res);
#endif

}

/*
 * given field of the form:   len1 word1 len2 word2 len3 word3 ...,
 * where each len is the length of the following "word",
 * search for word which is of the form len word_body where len is
 * the length of the word body
 */
#if MYSQL_S
my_bool
search_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return 0;
}

longlong
search(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
#else
Datum
search(PG_FUNCTION_ARGS)
#endif
{
    uint64_t wordLen;
    char * word = (char *)getba(ARGS, 0, wordLen);
    if (wordLen != (unsigned int)word[0]) {
        cerr << "ERR: wordLen is not equal to fist byte of word!!! ";
    }
    word = word + 1;     // +1 skips over the length field
    //cerr << "given expr to search for has " << wordLen << " length \n";

    uint64_t fieldLen;
    char *field = (char *) getba(ARGS, 1, fieldLen);

    //cerr << "searching for "; myPrint((unsigned char *)word, wordLen); cerr
    // << " in field "; myPrint((unsigned char *)field, fieldLen); cerr <<
    // "\n";

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




#if MYSQL_S

//TODO: write a version of search for postgres


my_bool
searchSWP_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	Token * t = new Token();

    uint64_t ciphLen;
    char *ciph = (char *) getba(args, 1, ciphLen);

    uint64_t wordKeyLen;
    char *wordKey = (char *) getba(args, 1, wordKeyLen);

	t->ciph = Binary((unsigned int) ciphLen, (unsigned char *)ciph);
	t->wordKey = Binary((unsigned int)wordKeyLen, (unsigned char *)wordKey);

	initid->ptr = (char *) t;

    return 0;
}

void
searchSWP_deinit(UDF_INIT *initid)
{
	 Token *t = (Token *) initid->ptr;
	 delete t;

}

my_bool
searchSWP(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)

{
    uint64_t wordLen;
    char * word = (char *)getba(ARGS, 0, wordLen);
    Binary w = Binary((unsigned int)wordLen, (unsigned char *)word);

    return search(*((Token *)(initid->ptr)), w);

 }


#endif




#if MYSQL_S

struct agg_state {
    ZZ sum;
    ZZ n2;
    bool n2_set;
    void *rbuf;
};

my_bool
agg_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    agg_state *as = new agg_state();
    as->rbuf = malloc(CryptoManager::Paillier_len_bytes);
    initid->ptr = (char *) as;
    return 0;
}

void
agg_deinit(UDF_INIT *initid)
{
    agg_state *as = (agg_state *) initid->ptr;
    free(as->rbuf);
    delete as;
}

void
agg_clear(UDF_INIT *initid, char *is_null, char *error)
{
    agg_state *as = (agg_state *) initid->ptr;
    as->sum = to_ZZ(1);
    as->n2_set = 0;
}

//args will be element to add, constant N2
my_bool
agg_add(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    agg_state *as = (agg_state *) initid->ptr;
    if (!as->n2_set) {
        ZZFromBytes(as->n2, (const uint8_t *) args->args[1],
                    args->lengths[1]);
        as->n2_set = 1;
    }

    ZZ e;
    ZZFromBytes(e, (const uint8_t *) args->args[0], args->lengths[0]);

    MulMod(as->sum, as->sum, e, as->n2);
    return true;
}

char *
agg(UDF_INIT *initid, UDF_ARGS *args, char *result,
    unsigned long *length, char *is_null, char *error)
{
    agg_state *as = (agg_state *) initid->ptr;
    BytesFromZZ((uint8_t *) as->rbuf, as->sum,
                CryptoManager::Paillier_len_bytes);
    *length = CryptoManager::Paillier_len_bytes;
    return (char *) as->rbuf;
}

#else

Datum
func_add(PG_FUNCTION_ARGS)
{
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

    if (DEBUG) {myPrint(bytesA, lenN2); }

    unsigned char * bytesRes = homomorphicAdd(bytesA, bytesB, bytesN2, lenN2);
    //cerr << "product "; myPrint(bytesRes, lenN2); cerr << " ";

    memcpy(VARDATA(input), bytesRes, lenN2);
    PG_RETURN_BYTEA_P(input);
}

Datum
func_add_final(PG_FUNCTION_ARGS)
{
    bytea * input = PG_GETARG_BYTEA_P(0);
    int lenN2 = (VARSIZE(input) - VARHDRSZ) / 2;

    bytea * res = (bytea *) palloc(lenN2 + VARHDRSZ);

    SET_VARSIZE(res, lenN2+VARHDRSZ);
    memcpy(VARDATA(res), VARDATA(input), lenN2);
    PG_RETURN_BYTEA_P(res);
}

#endif

// for update with increment
#if MYSQL_S
void
func_add_set_deinit(UDF_INIT *initid)
{
    if (initid->ptr)
        free(initid->ptr);
}

char *
func_add_set(UDF_INIT *initid, UDF_ARGS *args,
             char *result, unsigned long *length,
             char *is_null, char *error)
{
    if (initid->ptr)
        free(initid->ptr);

    uint64_t n2len = args->lengths[2];
    ZZ field, val, n2;
    ZZFromBytes(field, (const uint8_t *) args->args[0], args->lengths[0]);
    ZZFromBytes(val, (const uint8_t *) args->args[1], args->lengths[1]);
    ZZFromBytes(n2, (const uint8_t *) args->args[2], args->lengths[2]);

    ZZ res;
    MulMod(res, field, val, n2);

    void *rbuf = malloc((size_t)n2len);
    initid->ptr = (char *) rbuf;
    BytesFromZZ((uint8_t *) rbuf, res, (size_t)n2len);

    *length = (long unsigned int) n2len;
    return initid->ptr;
}

#else

Datum
func_add_set(PG_FUNCTION_ARGS)
{
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

    bytea * resBytea = (bytea *) palloc(N2Len + VARHDRSZ);
    SET_VARSIZE(resBytea, N2Len + VARHDRSZ);
    memcpy(VARDATA(resBytea), res, N2Len);
    PG_RETURN_BYTEA_P(resBytea);
}

#endif

} /* extern "C" */
