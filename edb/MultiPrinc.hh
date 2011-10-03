#pragma once

/*
 * MultiPrincipal.h
 *
 * Performs the high level multi-principal work: parsing and interaction with
 * key access.
 */

#include <edb/AccessManager.hh>
#include <edb/Translator.hh>


class MultiPrinc {
 public:
    MultiPrinc(Connect * conn);

    virtual
    ~MultiPrinc();

    /***  CREATE TABLES tasks ***/

    /*
     *
     * processes access link
     * sets wordsIt to next field to process in Create
     * updates encforMap and accMan
     * sets encryptfield
     */
    void processAnnotation(std::list<std::string>::iterator & wordsIt,
                           std::list<std::string> & words, std::string tablename,
                           std::string currentField,
                           bool & encryptfield, std::map<std::string,
                                                    TableMetadata *> & tm);

    int commitAnnotations();

    /*** LOGIN tasks ***/

    bool isActiveUsers(const std::string &query);

    bool checkPsswd(command comm, std::list<std::string> & words);

    /** FILTERS "WHERE" tasks **/

    //returns a map from encrypted field name to the value of field for which
    // it is encrypted e.g. text - 5 (val of gid)
    void getEncForFromFilter(command comm, std::list<std::string> query, TMKM & tmkm,
                             QueryMeta & qm, std::map<std::string,
                                                 TableMetadata *> &
                             tableMetaMap);

    /*** SELECT taks ***/

    // returns any additional fields that need to be requested from the DB
    // when table.field is requested
    std::string selectEncFor(std::string table, std::string field, QueryMeta & qm,
                        TMKM & tmkm, TableMetadata * tm,
                        FieldMetadata * fm);

    void prepareSelect(std::list<std::string> & words, TMKM & tmkm, QueryMeta & qm,
                       std::map<std::string,
                           TableMetadata *> & tm);

    // fills tmkm.encForReturned and decides if the next field was added by us
    // and should not be returned to the user
    void processReturnedField(unsigned int index, bool isNextSalt, std::string fullname, onion o,
                              TMKM & tmkm,
                              bool & ignore);

    bool checkPredicate(const AccessRelation & accRel, std::map<std::string, std::string> & vals);

    /*** INSERT tasks ***/

    //wordsIt points to the first value
    void insertRelations(const std::list<std::pair<std::string, bool> > & values, std::string table,
                         std::list<std::string> fields,
                         TMKM & tmkm);

    /*** OTHER ***/

    bool isPrincipal(std::string fullname);

    // -- Determines which key to use for a field
    // -- They return null if the set of active users cannot decrypt current
    // field
    // -- the key is to be used for a query
    std::string get_key(std::string fieldName, TMKM & tmkm);

    // -- Determines which key to use for a field
    // -- They return null if the set of active users cannot decrypt current
    // field
    // -- the key is to be used for a result set
    std::string get_key(std::string fieldName, TMKM & tmkm,
                   const std::vector<SqlItem> &res);

 private:
    Connect * conn;
    MultiKeyMeta mkm;
    KeyAccess * accMan;

};
