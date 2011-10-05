#pragma once

/*
 * cdb_rewrite.hh
 *
 *
 *  TODO: need to integrate it with util.h: some declarations are repeated
 */

#include <util/onions.hh>

using namespace std;

/**
 * Field here is either:
 * A) empty string, representing any field or
 * B) the field that the onion is key-ed on. this
 *    only has semantic meaning for DET and OPE
 */
typedef std::pair<SECLEVEL, std::string> LevelFieldPair;
typedef std::map<onion, LevelFieldPair>  OnionLevelFieldMap;
typedef std::pair<onion, LevelFieldPair> OnionLevelFieldPair;
typedef std::map<onion, SECLEVEL>        OnionLevelMap;

/**
 * Use to keep track of a field's encryption onions.
 */
class EncDesc {
public:
    EncDesc(OnionLevelMap input) : olm(input) {}
    EncDesc(const EncDesc & ed): olm(ed.olm) {}
    /**
     * Returns true if something was changed, false otherwise.
     */
    bool restrict(onion o, SECLEVEL maxl);

    OnionLevelMap olm;
};

/**
 * Used to keep track of encryption constraints during
 * analysis
 */
class EncSet {
public:
    EncSet(OnionLevelFieldMap input) : osl(input) {}
    EncSet(); // TODO(stephentu): move ctor here

    /**
     * decides which encryption scheme to use out of multiple in a set
     */
    EncSet chooseOne() const;

    EncSet intersect(const EncSet & es2) const;
    
    inline bool empty() const { return osl.empty(); }

    inline bool singleton() const { return osl.size() == 1; }

    inline OnionLevelFieldPair extract_singleton() const {
        assert(singleton());
        auto it = osl.begin();
        return OnionLevelFieldPair(it->first, it->second);
    }

    OnionLevelFieldMap osl; //max level on each onion
};

const EncDesc FULL_EncDesc = {
        {
            {oDET, SECLEVEL::SEMANTIC_DET},
            {oOPE, SECLEVEL::SEMANTIC_OPE},
            {oAGG, SECLEVEL::SEMANTIC_AGG},
            {oSWP, SECLEVEL::SWP         },
        }
};

const EncSet EQ_EncSet = {
        {
            {oDET, LevelFieldPair(SECLEVEL::DET, "")},
            {oOPE, LevelFieldPair(SECLEVEL::OPE, "")},
        }
};

const EncSet ORD_EncSet = {
        {
            {oOPE, LevelFieldPair(SECLEVEL::OPE, "")},
        }
};

//todo: there should be a map of FULL_EncSets depending on item type
const EncSet FULL_EncSet = {
        {
            {oDET, LevelFieldPair(SECLEVEL::SEMANTIC_DET, "")},
            {oOPE, LevelFieldPair(SECLEVEL::SEMANTIC_OPE, "")},
            {oAGG, LevelFieldPair(SECLEVEL::SEMANTIC_AGG, "")},
            {oSWP, LevelFieldPair(SECLEVEL::SWP,          "")},
        }
};

const EncSet Search_EncSet = {
        {
            {oSWP, LevelFieldPair(SECLEVEL::SWP, "")},
        }
};

const EncSet ADD_EncSet = {
        {
            {oAGG, LevelFieldPair(SECLEVEL::SEMANTIC_AGG, "")},
        }
};

const EncSet EMPTY_EncSet = {
        {{}}
};


/******* ENCRYPTED SCHEMA INFORMATION ********/


//TODO: FieldMeta and TableMeta are partly duplicates with the original
// FieldMetadata an TableMetadata
// which contains data we want to add to this structure soon
// we can remove old ones when we have needed functionality here
typedef struct FieldMeta {

    bool isEncrypted;     //indicates if this field is encrypted or not
    bool can_be_null;
		     
    
    fieldType type;
    std::string fieldName;

    enum_field_types mysql_type;

    map<onion, string> onionnames;
    EncDesc encdesc;
    
    bool has_salt; //whether this field has its own salt
    std::string salt_name;

    FieldMeta();

} FieldMeta;


typedef struct TableMeta {
   
    std::list<std::string> fieldNames;     //in order field names
    unsigned int tableNo;
    std::string anonTableName;
   
    std::map<std::string, FieldMeta *> fieldMetaMap;

    bool has_salt;
    std::string salt_name;


    bool hasEncrypted;     //true if the table contains an encrypted field

    TableMeta();
    ~TableMeta();
} TableMeta;


typedef struct SchemaInfo {
    std::map<std::string, TableMeta *> tableMetaMap;
    unsigned int totalTables;
    SchemaInfo():totalTables(0) {};
} SchemaInfo;

/***************************************************/


// metadata for field analysis
class FieldAMeta {
public:
    EncDesc exposedLevels; //field identifier to max sec level allowed to process a query
    FieldAMeta(const EncDesc & ed) : exposedLevels(ed) {}
};

//Metadata about how to encrypt an item
class ItemMeta {
public:
    onion o;
    SECLEVEL uptolevel;
    std::string basekey;
};

class Analysis {
public:
    Analysis(SchemaInfo * schema) : hasConverged(false), schema(schema) {
        // create mysql connection to embedded
        // server
        m = mysql_init(0);
        assert(m);
        mysql_options(m, MYSQL_OPT_USE_EMBEDDED_CONNECTION, 0);
        if (!mysql_real_connect(m, 0, 0, 0, 0, 0, 0, CLIENT_MULTI_STATEMENTS)) {
            mysql_close(m);
            fatal() << "mysql_real_connect: " << mysql_error(m);
        }
    }

   

    ~Analysis() {
        mysql_close(m);
    }

    inline MYSQL* conn() {
        mysql_thread_init();
        return m;
    }

    std::map<std::string, FieldAMeta *> fieldToAMeta;
    std::map<Item*, ItemMeta *> itemToMeta;

    bool hasConverged;
    SchemaInfo * schema;
    


private:
    MYSQL *m;
};

class FieldReturned {
public:
    bool encrypted;
    bool includeInResult;
    std::string key;
    unsigned int SaltIndex;
    std::string nameForReturn;
};

class ReturnMeta {
public:
    std::vector<FieldReturned *> retFM;
};


class constraints {
public:
    constraints(EncSet t_arg,
                const std::string &why_t_arg,
                Item *why_t_item_arg,
                const constraints *parent_arg)
    : encset(t_arg), soft(false),
      why_t(why_t_arg), why_t_item(why_t_item_arg),
      parent(parent_arg)
    {
        if (parent && parent->soft)
            soft = true;
    }

    constraints(EncSet t_arg,
                const std::string &why_t_arg,
                Item *why_t_item_arg,
                const constraints *parent_arg,
                bool soft_arg)
    : encset(t_arg), soft(soft_arg),
      why_t(why_t_arg), why_t_item(why_t_item_arg),
      parent(parent_arg)
    {
    }

    inline constraints
    clone_with(const EncSet &e) const
    {
        return constraints(e, why_t, why_t_item, parent, soft);
    }

    EncSet encset;
    SchemaInfo * schema;

    bool soft;      /* can be evaluated at proxy */

    std::string why_t;
    Item *why_t_item;

    const constraints *parent;
};


class Rewriter {

public:
    Rewriter(const std::string & db);
    std::string rewrite(const std::string &q, ReturnMeta &rmeta);    
private:

    string db;
    
    SchemaInfo *  schema;
    
    unsigned int totalTables;
    unsigned int totalIndexes;

};
