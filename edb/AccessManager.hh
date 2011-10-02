#pragma once

/*
 * AccessManager.h
 *
 *
 */

#include <string>
#include <map>
#include <set>
#include <list>

#include <edb/Connect.hh>
#include <crypto-old/CryptoManager.hh>


/*
 * This class maintains the flow of access based on user-annotated schema.
 *
 * a user refers to a physical user
 * a principal refers to a field in the database that has encrypted entries
 *  and/or has other fields encrypted for it
 * a generic principal is a collection of principal that all refer to the same
 *  values
 *
 *
 * ASSUMPTION: only terminal (does not have access to anything) principals 
 *  have > THRESHOLD keys
 *
 */

//TODO: fix PRINCVALUE to be application dependent
#define PRINCTYPE "varchar(100)"
#define PRINCVALUE "varchar(255)"
#define TESTING 1
#define THRESHOLD 100

typedef struct Prin {
    //the name of the principal (either a generic or a principal)
    std::string type;
    //the value of the principal
    std::string value;
    //the generic this Prin is part of (if it's already a generic, this is the
    // same)
    std::string gen;
    //for example, the Prin describing g.gid = 5, will have type g.gid and
    // value 5 and gen 0001ggid

    Prin()
    {
    }

    Prin(std::string typearg, std::string valuearg)
    {
        type = typearg;
        value = valuearg;
        gen = "";
    }

    bool
    operator<(const Prin &a) const
    {
        if (gen.compare(a.gen) != 0) {
            return (gen < a.gen);
        }
        return (value < a.value);
    };

    bool
    operator==(const Prin &a) const
    {
        return ((gen.compare(a.gen) == 0) && (value.compare(a.value) == 0));
    }

    bool
    operator!=(const Prin &a) const
    {
        return ((gen.compare(a.gen) != 0) || (value.compare(a.value) != 0));
    }

    std::string
    toString()
    {
        return type + " " + value;
    }
} Prin;

typedef struct PrinKey {
    std::string key;

    // principals currently holding the keys to access this key
    std::set<Prin> principals_with_access;

    bool
    operator==(const PrinKey &a) const
    {
        return a.key == key;
    }
} PrinKey;

class MetaAccess {
 public:
    MetaAccess(Connect * c, bool verb);

    //defines two names that refer to the same principal
    void addEquals(std::string princ1, std::string princ2);
    //calls addEquals after the access tree has been established
    //returns: 0  if the equality was added
    //         <0 if adding the equality would break the access tree
    int addEqualsCheck(std::string princ1, std::string princ2);

    //princHasAccess has access to princAccessible
    void addAccess(std::string princHasAccess, std::string princAccessible);
    //calls addAccess after the access tree has been established
    //returns: 0  if the access link was added
    //         <0 if adding the access link would break the access tree
    int addAccessCheck(std::string princHasAccess, std::string princAccessible);

    //adds princ to the set of principals which can give a password
    void addGives(std::string princ);
    //calls addGives after the access tree has been established
    //returns: 0  if the access link was added
    //         <0 if adding the access link would break the access tree
    int addGivesCheck(std::string princ);

    //prints out all the information stored in memory
    void PrintMaps();

    //populates the database with the tables for each access link
    //this method should only be called once, after all the access and equals
    // links have been added
    int CreateTables();

    bool CheckAccess();

    //drops all the tables create in CreateTables from the database
    int DeleteTables();

    //all four of the following functions only go one step along the access
    // graph
    //returns the set of all principals (not generics) that can immediately
    // access princ
    //does not include princ or any type which princ equals
    std::set<std::string> getTypesAccessibleFrom(std::string princ);
    //returns the set of all principals (not generics) that princ has
    // immediate access to
    //does not include princ or any type which princ equals
    std::set<std::string> getTypesHasAccessTo(std::string princ);
    //returns the set of all generics that can immediately access gen
    //includes gen
    std::set<std::string> getGenAccessibleFrom(std::string gen);
    //returns the set of all generics that gen has immediate access to
    //includes gen
    std::set<std::string> getGenHasAccessTo(std::string gen);

    //returns the set of all the principals (not generics) that are equal to
    // principal princ
    std::set<std::string> getEquals(std::string princ);

    //returns true if princ gives passsword
    //requires: princ to be type not generic
    bool isGives(std::string princ);
    //same as isGives, but takes generic as input
    bool isGenGives(std::string gen);

    //gives generic for princ
    //requires: princ is already stored in MetaAccess
    std::string getGenericPublic(std::string princ);

    std::string publicTableName();
    std::string accessTableName();

    ~MetaAccess();

 private:
    std::string getGeneric(std::string princ);
    std::string createGeneric(std::string clean_princ);

    //requires unsanitized to be of the form table.field (exactly one '.')
    std::string sanitize(std::string unsanitized);
    std::string unsanitize(std::string sanitized);
    std::set<std::string> unsanitizeSet(std::set<std::string> sanitized);

    //user-supplied principal to generic principal
    std::map<std::string, std::string> prinToGen;
    //generic principal to user-supplied principals
    std::map<std::string, std::set<std::string> > genToPrin;

    //maps the principals which have access to things to the principals they
    // have access to
    std::map<std::string, std::set<std::string> > genHasAccessToList;
    //maps the principals which are accessible by things to the principals
    // they are accessible by
    std::map<std::string, std::set<std::string> > genAccessibleByList;

    //keeps track of principals which can give passwords
    std::set<std::string> givesPsswd;

    //wrapper for conn->execute
    int execute(std::string sql);

    Connect * conn;
    bool VERBOSE;
    std::string public_table;
    std::string access_table;
};

class KeyAccess {
 public:
    KeyAccess(Connect * connect);

    //meta access functions
    //defines two names that refer to the same principal
    int addEquals(std::string prin1, std::string prin2);
    //princHasAccess has access to princAccessible
    int addAccess(std::string hasAccess, std::string accessTo);
    //adds princ to the set of principals which can give a password
    int addGives(std::string prin);
    //this method should only be called once, after all the access and equals
    // links have been added
    int CreateTables();
    //returns the set of all principals (not generics) that can immediately
    // access princ
    //does not include princ or any type which princ equals
    std::set<std::string> getTypesAccessibleFrom(std::string princ);
    //returns the set of all principals (not generics) that princ has
    // immediate access to
    //does not include princ or any type which princ equals
    std::set<std::string> getTypesHasAccessTo(std::string princ);
    //returns the set of all generics that can access gen
    //does include gen
    std::set<std::string> getGenAccessibleFrom(std::string gen);
    //returns the set of all generics that gen has access to
    //does include gen
    std::set<std::string> getGenHasAccessTo(std::string gen);
    //returns the set of all the principals (not generics) that are equal to
    // principal princ
    std::set<std::string> getEquals(std::string princ);

    //get generic public
    std::string getGeneric(std::string prin);

    void Print();

    bool isType(std::string type);

    //add a key for the principal hasAccess to access principal accessTo
    //input: both Prins are expected to not be generics
    //requires: if hasAccess is a givesPsswd, it must exist (KeyAccess cannot
    // generate password derived keys)
    //return: 0  if key is inserted successfully
    //        1  if key already existed
    //        <0 if an error occurs
    int insert(Prin hasAccess, Prin accessTo);

    //reverse insert on a particular hasAccess -> accessTo link
    //input: both Prins are expected not to be generics
    int remove(Prin hasAccess, Prin accessTo);

    //returns the symmetric key for the principal Prin, if held
    //  to discover if key is held (or should be held, in case of orphans)
    //  getKey checks first the local memory (keys) for online users keys
    //  if the key is not there, then it checks to see if the key should exist
    //  if the key should not exist (ie, prin is an orphan), a new key is
    //  generated and returned
    //  if prin isn't an orphan, getKey last checks to see if there are unCached
    //  keys for prin
    //returns keys of length AES_KEY_BYTES
    std::string getKey(Prin prin);

    //returns the symmetric key for the principal Prin, if held
    //returns keys of length AES_KEY_BYTES
    PrinKey getPrinKey(Prin prin);

    //returns the public key for the principal prin, NULL if prin is not found
    PKCS * getPublicKey(Prin prin);
    //returns the secret key for the principal prin
    //requires: access to prin's symmetric key
    PrinKey getSecretKey(Prin prin);

    //inserts a givesPsswd value
    //if the value has access to other principals, all those keys are accessed
    // and decrypted if there are fewer of them than THRESHOLD
    // if there are more keys than THRESHOLD, this Prin.type->Prin.type
    //   information is stored in uncached_keys
    //assumption: only terminal principals have > THRESHOLD keys
    //note: if we already hold a key for Prin gives in, it has no new keys and
    //        therefore no keys are loaded
    //requires: psswd be of length AES_KEY_BYTES
    //returns: 0 if insertPsswd inserted correctly
    //         1 if Prin gives key is already held
    //         <0 if there is an error in inserting any keys gives has access to
    int insertPsswd(Prin gives, const std::string &psswd);

    //removes a givesPsswd value
    //if the value is holding keys to other principals that no other inserted
    // givesPsswd value has access to, the keys are dropped from keys
    int removePsswd(Prin prin);

    ~KeyAccess();

 private:
    //describes keys currently held by the proxy
    std::map<Prin, PrinKey> keys;
    //describes uncached keys accessible in the database
    // the first string is the gen of the accessTo key; the second string is a
    //  gen which has access to the key, and the int is the number of values
    //  (Prins) which have uncached keys of the type of the first string
    std::map<std::string, std::map<std::string, int> > uncached_keys;

    //describe all chains disconnected from a physical principal
    std::map<Prin, std::set<Prin> > orphanToParents;
    std::map<Prin, std::set<Prin> > orphanToChildren;
    //the MetaAccess that described the possible access links
    MetaAccess * meta;
    CryptoManager * crypt_man;
    Connect * conn;
    bool VERBOSE;
    bool meta_finished;

    //wrapper for conn->execute, assuming that sql is a query that returns a result set
    ResType execute(std::string sql);

    //creates PrinKey
    //requires: hasAccess and accessTo to have gen field set
    PrinKey buildKey(Prin hasAccess, const std::string &sym_key);

    //adds prin to the map keys
    //if keys already holds this keys, the principals_with_access sets are
    // merged
    //returns: 0  if key added successfully
    //         1  if prin already has this key
    //         <0 if prin already has a different key
    int addToKeys(Prin prin, PrinKey key);

    //removes prin to the map keys
    //returns: 0  if key removed sucessfully
    //         1  if key does not exist
    //         <0 for other errors (none in place yet...)
    int removeFromKeys(Prin prin);

    //returns result of selecting hasAccess and accessTo from access_keys table
    //requires: either hasAccess or accessTo not to be NULL
    ResType SelectAccess(Prin hasAccess, Prin accessTo);
    int SelectAccessCount(Prin hasAccess, Prin accessTo);
    ResType SelectAccessCol(Prin hasAccess, Prin accessTo, std::string column);

    //returns result of selecting hasAccess and accessTo from access_keys table
    //requires: either hasAccess or accessTo not to be NULL
    ResType SelectPublic(Prin prin);
    int SelectPublicCount(Prin prin);
    ResType SelectPublicCol(Prin prin, std::string column);

    //removes the row from the access table hasAccess->accessTo that contains
    // the values of hasAccess.value and accessTo.value
    //requires: hasAccess.gen and accessTo.gen to exits
    //returns: 0  if row removed sucessfully
    //         <0 if an error occurs
    int RemoveRow(Prin hasAccess, Prin accessTo);

    //generates a public/secret asymmetric key pair for principal prin,
    // encrypts the secret key with key prin_key and stores the public key and
    // encrypted secret key in the public keys table
    //requires prin_key with key and len
    int GenerateAsymKeys(Prin prin, PrinKey prin_key);

    //removes orphan, and all descendants of orphan from the orphan graph
    int removeFromOrphans(Prin orphan);

    //returns: str_encrypted_key decrypted symmetrically with
    // key_for_decrypting
    //         principals_with_access is empty
    PrinKey decryptSym(const SqlItem &sql_encrypted_key,
                       const std::string &key_for_decrypting,
                       const SqlItem &sql_salt);

    PrinKey decryptAsym(const SqlItem &sql_encrypted_key,
                        const std::string &secret_key);

    bool isInstance(Prin prin);
    bool isOrphan(Prin prin);

#if TESTING
 public:
#endif
    //if prin has uncached keys, finds and returns them
    //requires: all keys in uncached_keys to have their principals still logged
    // on
    //returns: PrinKey for prin is exists
    //         empty PrinKey if prin does not have an accessible key
    PrinKey getUncached(Prin prin);

    //Bredth First Search for generics start has access to
    std::list<std::string> BFS_hasAccess(Prin start);

    //Depth First Search for generics start has access to
    std::list<std::string> DFS_hasAccess(Prin start);

    int DeleteTables();

};
