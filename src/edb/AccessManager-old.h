/*
 * AccessManager.h
 *
 * receives == secondary == hasaccess
 * gives == primary == accessto
 *
 */

#ifndef ACCESSMANAGER_H_
#define ACCESSMANAGER_H_

#include "util.h"



#include <string>
#include <map>
#include <list>
#include "Connect.h"
#include "CryptoManager.h"


/*
 * This class maintains the flow of access based on user-annotated schema.
 *
 * To clarify the documentation of this class, consider the following annotation example:
 *   Table u: (uid ACCESSTO uname, uname GIVESPSSWD);
 *   Table g: (gid ACCESSTO uid, uid EQUALS u.uid);
 *   Table f: (fid, gid EQUALS g.gid, name ENCFOR gid, text ENCFOR gid);
 */

/*
 * Simplifications (for now):
 *  - you can assume all fields are integer-valued
 *  - whenever you need to insert or remove something, the needed users will be online so you will always have the keys you need so you don't need to do any public key crypto
 *  - we do not have to worry about revoking users yet
 */

/*
 * Implementation aids:
 * - to transform from unsigned char * to  bytea encoding to include in an sql query use marshallBinary and unmarshallBinary from util.h
 * - to generate a random key, use randomBytes from util.h
 * - to encrypt an aes key with other aes key use
 * - to encrypt a key with probabilistic encryption for another key use these functions from CryptoManager.h:
 *   unsigned char * encrypt_SEM(unsigned char * & ptext, unsigned int len, AES_KEY * key, uint64_t salt);
	 unsigned char * decrypt_SEM(unsigned char * ctext, unsigned int len, AES_KEY * key, uint64_t salt);
   - in general, peak at my files or give me a call
 */

typedef struct PrincipalMeta {
	list<string> usernames; //usernames logged in with access to this principal
	//true if there is yet no link between a username and this principals' key
	// bool isOrphan;
	unsigned char * key; //principal key
	unsigned int len; //principal len
} PrincipalMeta;


class AccessManager {
public:

	//store this object and execute conn->execute(const char *query) to send queries to the db;
	//the results will be in pgresult * format which is easy to parse (see examples in rewriteDecryptSelect() in EDBClient.cc)
	//there is no encryption needed here because these are key/metadata tables so plain_execute avoids CryptDB encryption
	AccessManager(Connect * connect);

	//ERROR MSG CONVENTION
	// 0 = OK
	// <0 = ERROR
	//>0 = the operation was not completed because it was not needed (eg. inserting smth that exists)

	// SETUP ACCESS FLOW

	//creates empty table with the schema: CREATE TABLE somename (gives text, receives text, key bytea, salt bigint);
	//for example, for the call addAccessTo("g.gid", "g.uid")
	// Table
	// | g.gid | g.uid | key     | salt
	// | 3   |   5 | E_k5[k_g3]  | 387454
	// | 4   |   6 | E_k6[k_g4]  | 321951
	// | 3   |   9 | E_k3[k_g3]  | 319327
	//                  ^
	//                  |
	//assume you mean 9/
	// the key field contains the key of gid encrypted with the key for uid; for the same group, it should be the same key as in the example
	// just create the table, we will add values in it when I call insert and tell you concrete values of gid and uid
	// for the example above, I will make these calls: addAccessTo("u.uid", "u.uname"), addAccessTo("g.gid", "g.uid");
	//
	//
	// return negative value if any issue pops up (same for all other functions)
	//can be multiple hasacess to a given accessto
	int addAccessTo(string accessto, string hasaccess);

	// for example, addEquals("g.gid", "u.uid")
	//record the fact that these fields are in fact the same; record this in a map locally, no need for table insertion
	int addEquals(string field1, string field2);
	//for example, givesPsswd("u.uname")
	// just record this locally for your later use (no need for DB storage)
	int givesPsswd(string gives);

	//returns all the fields that have access to "accessto"
	//fields in the same table with accessto are placed first
	//empty list means not such field
	list<string> hasAccess(string accessTo);

	//returns fields have have access to "accessTo" from the same table
	list<string> inTableHasAccess(string accessTo);


	//returns all the fields to which "hasaccess" has access
	//first fields in the list are elements in the same table
	//empty list means not such field
	list<string> accessTo(string hasAccess);

	string inTableAccessTo(string hasAccess);


	//you don't have to deal with ENCFOR, I'll do that outside in CryptDB

	//INSERTING VALUES

	//maintain an activeUsers mapping (no need to make this a table, can be a local map)
	// this function records the private key of username
	//psswd is AES_KEY_BYTES long
	//return negative on failure or if this was already in the map
	int insertPsswd(string username, unsigned char * psswd);
	// removes the entry inserted
	//returns negative on failure or if there was no entry for username
	int deletePsswd(string username);

	//for example, fields = (g.gid, g.uid), ids = (3, 5) like in the example table above
	// at this point, you have to select a key for gid at random *if* gid does not have one already (which you can establish by queries Table access)
	// this key needs to be encrypted with the key of uid; you can fetch this key from the access table containing u.uid, u.name, key;
	// users will always be online for operations needing them (I will have provided you the private key with insertPsswd)
	//int insert(list<string> fields, list<int> ids);
	int insert(list<string> fields, list<string> ids);

	//reverses the effect of insert
	int remove(list<string> fields, list<string> ids);

	//FETCHING KEYS


	// return the key for the field called encryptedForField when its value is encryptedForValue
	//eg., getKey("f.gid", 3): return the key of group 3: k_g3
	// to do this you will have to use the tables you built in addAccessTo and addEquals
	//for our example, you will have to backtrack based on the group value through users id until you reach a username that provided a password enabling you to obtain this key
	// return NULL if something went wrong
	//unsigned char * getKey(string encryptedForField, int encryptedForValue);
	unsigned char * getKey(string encryptedForField, string encryptedForValue);

	//gets the public key for the specified username
	unsigned char * getPublicKey(string username, unsigned int& length);

	//for testing purposes only
	unsigned char * mykey;	
	
	void savekey(string field, int value);
	void savekey(string field, string value);

	void finish();

	virtual ~AccessManager();

	bool VERBOSE;

	string PrunePeriods(string input);
	string UnPrune(string input);
	list<string> UnPrune(list<string> vals);

private:
	//connection to db
	Connect *conn;
	//maps secondary keys of a table to another tables primary key
	//stores equals
	// (eg guid -> uuid)
	map<string, string> access_map;
	//maps primary key of a table to equivalent secondary key
	//stores equals the other direction
	// (eg uuid -> guid)
	map<string, string> access_map_r;
	//maps givespassword field value to secret key
	map<string, unsigned char*> password_map;
	map<string, int> password_len;

	//maps secondary keys to table names
	// that is, fields_to_table[g.uid] tells you where g.uid's keys are
	//maps an hasaccess to a table with accessto and has access
	// table [u.uid] -> table with (u.uid and u.gid);
	map<string, string> fields_to_table;
	//maps username to ALL of their decrypted keys
	// of the form: user_keys[username][primary field][value] = key for user
	// of the form: user_keys[username][accessto][value] = key for user
	//              to decrypt primary field
	map<string, map< string, map<string, bool> > > user_keys;


	//[primary field][value][PrincipalMeta]
	//e.g. [g.gid][2][...]
	map<string, map<string, PrincipalMeta> > fast_keys;

	//the basic name for all the tables
	string table_name;
	//the number of tables we currently have (used in naming)
	unsigned int table_num;
	//the fieldname which gives a password
	// tuples of the form (field, principle), with principle as the indexable field
	// principle refers to the principle you uses this field to get its key
	string gives_pass;
	//the encryption manager
	CryptoManager *crypt_man;
	//testing fields
	string savefield;
	string savevalue;
	int saveval;

	//maps primary key to secondary key in same table
	// (eg ggid -> guid)
	map<string, list<string> > accessToRelations;

	//maps secondary key to primary key in same table
	// (eg guid -> ggid)
	map<string, string> accessToRelations_r;

	// INTERNAL FUNCTIONS
	// -- all receive and return pruned fields

	//helper functions
	void addToMap(string field, string val, string username, unsigned char * key, int len);
	//returns true if smth was deleted
	bool removeFromMap(string princ, string val, string username);
	void processInsert(string username, string field, list<string> ids, list<string> fields, unsigned char * key);
	//returns all fields equal to this field
	vector<string> getEqualsFields(string field);

	//returns true if this princ, val is not seen before
	bool isOrphan(string princ, string val);

	unsigned char * findKey(string field, string val);

    bool getPrinc(string princ, string val, PrincipalMeta & pm);

    //returns true if the given principal instance is present in some table
    bool princInstanceInTables(string princ, string val);

    //returns a nonempty string if princ and val have some equals field that has a key in fast_keys
    string equalsHasKey(string princ, string val);

    //same thing as getKey, receives pruned fields
    unsigned char * internalGetKey(string encryptedFor, string encryptedForValue);


};



#endif /* ACCESSMANAGER_H_ */
