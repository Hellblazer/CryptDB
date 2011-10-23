#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <set>
#include <list>
#include <algorithm>
#include <stdio.h>

#include <parser/cdb_rewrite.hh>

#define UNIMPLEMENTED \
    throw runtime_error(string("Unimplemented: ") + \
                        string(__PRETTY_FUNCTION__))

using namespace std;

static inline void
mysql_query_wrapper(MYSQL *m, const string &q)
{
    if (mysql_query(m, q.c_str())) {
        cryptdb_err() << "query failed: " << q
                << " reason: " << mysql_error(m);
    }

    // HACK(stephentu):
    // Calling mysql_query seems to have destructive effects
    // on the current_thd. Thus, we must call create_embedded_thd
    // again.
    void* ret = create_embedded_thd(0);
    if (!ret) assert(false);
}


static inline bool
FieldQualifies(const FieldMeta * restriction,
               const FieldMeta * field)
{
    return !restriction || restriction == field;
}

static inline bool
IsMySQLTypeNumeric(enum_field_types t) {
    switch (t) {
        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_TINY:
        case MYSQL_TYPE_SHORT:
        case MYSQL_TYPE_LONG:
        case MYSQL_TYPE_FLOAT:
        case MYSQL_TYPE_DOUBLE:
        case MYSQL_TYPE_LONGLONG:
        case MYSQL_TYPE_INT24:
        case MYSQL_TYPE_NEWDECIMAL:

        // numeric also includes dates for now,
        // since it makes sense to do +/- on date types
        case MYSQL_TYPE_TIMESTAMP:
        case MYSQL_TYPE_DATE:
        case MYSQL_TYPE_TIME:
        case MYSQL_TYPE_DATETIME:
        case MYSQL_TYPE_YEAR:
        case MYSQL_TYPE_NEWDATE:
            return true;
        default: return false;
    }
}

static string
getAnonName(const ItemMeta * im) {
    return im->basefield->onionnames[im->o];
}

//TODO raluca: should unify enc/dec for numeric and strings
static fieldType
getTypeForDec(const ItemMeta * im) {
    if (IsMySQLTypeNumeric(im->basefield->sql_field->sql_type)) {
	return TYPE_INTEGER;
    } else {
	return TYPE_TEXT;
    }
}


static void
addToReturn(ReturnMeta & rm, int pos, ItemMeta * im, bool has_salt) {
    ReturnField rf = ReturnField();
    rf.is_salt = false;
    rf.im = im;
    if (has_salt) {
	rf.pos_salt = pos+1;
    } else {
	rf.pos_salt = -1;
    }
    rm.rfmeta[pos] = rf;
}


static void
addSaltToReturn(ReturnMeta & rm, int pos) {
    ReturnField rf = ReturnField();
    rf.is_salt = true;
    rf.im = NULL;
    rf.pos_salt = -1;
    rm.rfmeta[pos] = rf;
}



static inline string
sq(MYSQL *m, const string &s)
{
    char buf[s.size() * 2 + 1];
    size_t len = mysql_real_escape_string(m, buf, s.c_str(), s.size());
    return string("'") + string(buf, len) + string("'");
}

/********  parser utils; TODO: put in separate file **/

static string
ItemToString(Item * i) {
    String s;
    String *s0 = i->val_str(&s);
    assert(s0 != NULL);
    return string(s0->ptr(), s0->length());
}

// encrypts a constant item based on the information in a
static string
encryptConstantItem(Item * i, const Analysis & a){
    string plaindata = ItemToString(i);

    auto itemMeta = a.itemToMeta.find(i);
    assert_s(itemMeta != a.itemToMeta.end(), "there is no meta for item in analysis");

    ItemMeta * im = itemMeta->second;
    FieldMeta * fm = im->basefield;

    string anonname = fullName(fm->onionnames[im->o], fm->tm->anonTableName);
    bool isBin;
    return a.cm->crypt(a.cm->getmkey(), plaindata, TYPE_TEXT,
                       anonname, getMin(im->o), fm->encdesc.olm[im->o], isBin);
}

/***********end of parser utils *****************/

/*static
void print(const map<string, TableMeta*>& t) {
    cerr<<"tables ";
    for (auto p:t) {
        cerr << p.first << " ";
    }
    cerr << "\n";
}
*/
bool
EncDesc::restrict(onion o, SECLEVEL maxl)
{
    //TODO:
    //assert(maxl is on onion o);

    auto it = olm.find(o);
    assert(it != olm.end());

    if (it->second > maxl) {
        it->second = maxl;
        return true;
    }

    return false;
}

EncSet::EncSet() : osl(FULL_EncSet.osl) {}

EncSet
EncSet::intersect(const EncSet & es2) const
{
    OnionLevelFieldMap m;
    for (auto it2 = es2.osl.begin();
         it2 != es2.osl.end(); ++it2) {
        auto it = osl.find(it2->first);
        if (it != osl.end()) {
            SECLEVEL sl = (SECLEVEL)min((int)it->second.first,
                                        (int)it2->second.first);
            if (it->second.second == NULL) {
                m[it->first] = LevelFieldPair(
                        sl, it2->second.second);
            } else if (it2->second.second == NULL) {
                m[it->first] = LevelFieldPair(
                        sl, it->second.second);
            } else if (it->second.second == it2->second.second) {
                m[it->first] = LevelFieldPair(
                        sl, it->second.second);
            }
        }
    }
    return EncSet(m);
}

EncSet
EncSet::chooseOne() const
{
    // Order of selection is encoded in this array.
    // The onions appearing earlier are the more preferred ones.
    static const onion onion_order[] = {
        oDET,
        oOPE,
        oAGG,
        oSWP,
    };
    static size_t onion_size = sizeof(onion_order) / sizeof(onion_order[0]);
    for (size_t i = 0; i < onion_size; i++) {
        auto it = osl.find(onion_order[i]);
        if (it != osl.end()) {
            OnionLevelFieldMap m;
            m[onion_order[i]] = it->second;
            return EncSet(m);
        }
    }
    return EncSet(OnionLevelFieldMap());
}

static ostream&
operator<<(ostream &out, const EncSet & es)
{
    if (es.osl.size() == 0) {
        out << "empty encset";
    }
    for (auto it : es.osl) {
        out << "(onion " << it.first
            << ", level " << levelnames[(int)it.second.first]
            << ", field `" << (it.second.second == NULL ? "*" : it.second.second->fname) << "`"
            << ") ";
    }
    return out;
}

static ostream&
operator<<(ostream &out, const EncDesc & ed)
{
    if (ed.olm.size() == 0) {
        out << "empty encdesc";
    }
    for (auto it : ed.olm) {
        out << "(onion " << it.first
            << ", level " << levelnames[(int)it.second]
            << ") ";
    }
    return out;
}

static ostream&
operator<<(ostream &out, const constraints &r)
{
    out << r.encset;
    if (r.soft)
        out << "(soft)";
    out << " NEEDED FOR " << r.why_t;
    if (r.why_t_item)
        out << " in " << *r.why_t_item;
    if (r.parent)
        out << " BECAUSE " << *r.parent;
    return out;
}

static ostream&
operator<<(ostream &out, const OnionLevelFieldPair &p)
{
    out << "(onion " << p.first
        << ", level " << levelnames[(int)p.second.first]
        << ", field `" << (p.second.second == NULL ? "*" : p.second.second->fname) << "`"
        << ")";
    return out;
}

static char *
make_thd_string(const string &s, size_t *lenp = 0)
{
    THD *thd = current_thd;
    assert(thd);

    if (lenp)
        *lenp = s.size();
    return thd->strmake(s.data(), s.size());
}

static string
anonymize_table_name(const string &tname,
                     Analysis & a)
{
    // TODO(stephentu):
    // A) do an actual mapping
    // B) figure out where to actually allocate the memory for strs
    //    (right now, just putting it in the THD mem pools)

    //hack for now, will fix soon
    if (a.schema->tableMetaMap.find(tname) == a.schema->tableMetaMap.end()) {
        return tname;
    } else {
        return a.schema->tableMetaMap[tname]->anonTableName;
    }
}

static string
get_column_name(const string & table,
                const string & field,
                onion o,
                Analysis   &a)
{
    auto it = a.schema->tableMetaMap.find(table);
    if (it == a.schema->tableMetaMap.end()) {
        thrower() << "table " << table << "unknown \n";
    }
    auto fit = it->second->fieldMetaMap.find(field);
    if (fit == it->second->fieldMetaMap.end()) {
        thrower() << "field " << field << "unknown \n";
    }
    return fit->second->onionnames[o];
}

class CItemType {
 public:
    virtual EncSet do_gather(Item *, const constraints&, Analysis &) const = 0;
    virtual void   do_enforce(Item *, const constraints&, Analysis &) const = 0;
    virtual Item * do_optimize(Item *, Analysis &) const = 0;
    virtual Item * do_rewrite(Item *, Analysis &) const = 0;
    virtual void   do_rewrite_proj(Item *, Analysis &, vector<Item *> &) const = 0;
    virtual void   do_rewrite_insert(Item *, Analysis &, vector<Item *> &, FieldMeta *fm) const = 0;
};


/*
 * Directories for locating an appropriate CItemType for a given Item.
 */
template <class T>
class CItemTypeDir : public CItemType {
 public:
    void reg(T t, CItemType *ct) {
        auto x = types.find(t);
        if (x != types.end())
            thrower() << "duplicate key " << t;
        types[t] = ct;
    }

    EncSet do_gather(Item *i, const constraints &tr, Analysis &a) const {
        return lookup(i)->do_gather(i, tr, a);
    }

    void do_enforce(Item *i, const constraints &tr, Analysis &a) const {
        lookup(i)->do_enforce(i, tr, a);
    }

    Item* do_optimize(Item *i, Analysis &a) const {
        return lookup(i)->do_optimize(i, a);
    }

    Item* do_rewrite(Item *i, Analysis &a) const {
        return lookup(i)->do_rewrite(i, a);
    }

    void do_rewrite_proj(Item *i, Analysis &a, vector<Item *> &l) const {
        lookup(i)->do_rewrite_proj(i, a, l);
    }

    void do_rewrite_insert(Item *i, Analysis &a, vector<Item *> &l, FieldMeta *fm) const {
        lookup(i)->do_rewrite_insert(i, a, l, fm);
    }

 protected:
    virtual CItemType *lookup(Item *i) const = 0;

    CItemType *do_lookup(Item *i, T t, const char *errname) const {
        auto x = types.find(t);
        if (x == types.end())
            thrower() << "missing " << errname << " " << t << " in " << *i;
        return x->second;
    }

 private:
    std::map<T, CItemType*> types;
};

static class ANON : public CItemTypeDir<Item::Type> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, i->type(), "type");
    }

} itemTypes;

static class CItemFuncDir : public CItemTypeDir<Item_func::Functype> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, ((Item_func *) i)->functype(), "func type");
    }
 public:
    CItemFuncDir() {
        itemTypes.reg(Item::Type::FUNC_ITEM, this);
        itemTypes.reg(Item::Type::COND_ITEM, this);
    }
} funcTypes;

static class CItemSumFuncDir : public CItemTypeDir<Item_sum::Sumfunctype> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, ((Item_sum *) i)->sum_func(), "sumfunc type");
    }
 public:
    CItemSumFuncDir() {
        itemTypes.reg(Item::Type::SUM_FUNC_ITEM, this);
    }
} sumFuncTypes;

static class CItemFuncNameDir : public CItemTypeDir<std::string> {
    CItemType *lookup(Item *i) const {
        return do_lookup(i, ((Item_func *) i)->func_name(), "func name");
    }
 public:
    CItemFuncNameDir() {
        funcTypes.reg(Item_func::Functype::UNKNOWN_FUNC, this);
        funcTypes.reg(Item_func::Functype::NOW_FUNC, this);
    }
} funcNames;


/*
 * Helper functions to look up via directory & invoke method.
 */
static inline EncSet
gather(Item *i, const constraints &tr, Analysis & a)
{
    return itemTypes.do_gather(i, tr, a);
}

static inline void
enforce(Item *i, const constraints &tr, Analysis & a)
{
    return itemTypes.do_enforce(i, tr, a);
}

static inline void
analyze(Item *i, const constraints &tr, Analysis & a)
{
    EncSet e(gather(i, tr, a));
    e = e.chooseOne();
    enforce(i, tr.clone_with(e), a);
}

static inline void
optimize(Item **i, Analysis &a) {
    Item *i0 = itemTypes.do_optimize(*i, a);
    if (i0 != *i) {
        // item i was optimized (replaced) by i0

        // don't delete explicitly, b/c this is handled by
        // deleting the lex
        // delete *i;

        *i = i0;
    }
}

// TODO: template this with optimize()
static inline void
rewrite(Item **i, Analysis &a) {
    Item *i0 = itemTypes.do_rewrite(*i, a);
    if (i0 != *i) {
        i0->name = (*i)->name; // preserve the name (alias)
        *i = i0;
    }
    i0->name = NULL; // HACK(stephentu): drop the aliases for now
}

template <class T>
static Item *
do_optimize_const_item(T *i, Analysis &a) {
    if (i->const_item()) {
        // ask embedded DB to eval this const item,
        // then replace this item with the eval-ed constant
        //
        // WARNING: we must make sure that the primitives like
        // int literals, string literals, override this method
        // and not ask the server.

        // very hacky...
        stringstream buf;
        buf << "SELECT " << *i;
        string q(buf.str());

        MYSQL *m = a.conn();
        mysql_query_wrapper(m, q);

        THD *thd = current_thd;
        assert(thd != NULL);

        MYSQL_RES *r = mysql_store_result(m);
        if (r) {
            Item *rep = NULL;

            assert(mysql_num_rows(r) == 1);
            assert(mysql_num_fields(r) == 1);

            MYSQL_FIELD *field = mysql_fetch_field_direct(r, 0);
            assert(field != NULL);

            MYSQL_ROW row = mysql_fetch_row(r);
            assert(row != NULL);

            char *p = row[0];
            unsigned long *lengths = mysql_fetch_lengths(r);
            assert(lengths != NULL);

            if (p) {

//enum enum_field_types { MYSQL_TYPE_DECIMAL, MYSQL_TYPE_TINY,
//            MYSQL_TYPE_SHORT,  MYSQL_TYPE_LONG,
//            MYSQL_TYPE_FLOAT,  MYSQL_TYPE_DOUBLE,
//            MYSQL_TYPE_NULL,   MYSQL_TYPE_TIMESTAMP,
//            MYSQL_TYPE_LONGLONG,MYSQL_TYPE_INT24,
//            MYSQL_TYPE_DATE,   MYSQL_TYPE_TIME,
//            MYSQL_TYPE_DATETIME, MYSQL_TYPE_YEAR,
//            MYSQL_TYPE_NEWDATE, MYSQL_TYPE_VARCHAR,
//            MYSQL_TYPE_BIT,
//                        MYSQL_TYPE_NEWDECIMAL=246,
//            MYSQL_TYPE_ENUM=247,
//            MYSQL_TYPE_SET=248,
//            MYSQL_TYPE_TINY_BLOB=249,
//            MYSQL_TYPE_MEDIUM_BLOB=250,
//            MYSQL_TYPE_LONG_BLOB=251,
//            MYSQL_TYPE_BLOB=252,
//            MYSQL_TYPE_VAR_STRING=253,
//            MYSQL_TYPE_STRING=254,
//            MYSQL_TYPE_GEOMETRY=255
//};

                cerr << "p: " << p << endl;
                cerr << "field->type: " << field->type << endl;

                switch (field->type) {
                    case MYSQL_TYPE_SHORT:
                    case MYSQL_TYPE_LONG:
                    case MYSQL_TYPE_LONGLONG:
                    case MYSQL_TYPE_INT24:
                        rep = new Item_int((long long) strtoll(p, NULL, 10));
                        break;
                    case MYSQL_TYPE_FLOAT:
                    case MYSQL_TYPE_DOUBLE:
                        rep = new Item_float(p, lengths[0]);
                        break;
                    case MYSQL_TYPE_DECIMAL:
                    case MYSQL_TYPE_NEWDECIMAL:
                        rep = new Item_decimal(p, lengths[0], i->default_charset());
                        break;
                    case MYSQL_TYPE_VARCHAR:
                    case MYSQL_TYPE_VAR_STRING:
                        rep = new Item_string(thd->strdup(p),
                                              lengths[0],
                                              i->default_charset());
                        break;
                    default:
                        // TODO(stephentu): implement the rest of the data types
                        break;
                }
            } else {
                // this represents NULL
                rep = new Item_null();
            }
            mysql_free_result(r);
            if (rep != NULL) return rep;
        } else {
            // some error in dealing with the DB
            cerr << "could not retrieve result set" << endl;
        }
    }
    return i;
}

template <class T>
static Item *
do_optimize_type_self_and_args(T *i, Analysis &a) {
    Item *i0 = do_optimize_const_item(i, a);
    if (i0 == i) {
        // no optimizations done at top level
        // try children
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            optimize(&args[x], a);
        }
        return i;
    } else {
        return i0;
    }
}

static void
record_item_meta_for_constraints(Item *i,
                                 const constraints &tr,
                                 Analysis &a)
{
    auto c = tr.encset.extract_singleton();
    cerr << "Need to encrypt " << *i << " with: " << c << endl;
    auto it = a.itemToMeta.find(i);
    ItemMeta *im;
    if (it == a.itemToMeta.end()) {
        a.itemToMeta[i] = im = new ItemMeta;
    } else {
        im = it->second;
    }
    im->o         = c.first;
    im->uptolevel = c.second.first;
    im->basefield = c.second.second;
}

template <class T>
static Item *
do_rewrite_type_args(T *i, Analysis &a) {
    Item **args = i->arguments();
    for (uint x = 0; x < i->argument_count(); x++) {
        rewrite(&args[x], a);
        args[x]->name = NULL; // args should never have aliases...
    }
    return i;
}

/*
 * CItemType classes for supported Items: supporting machinery.
 */
template<class T>
class CItemSubtype : public CItemType {
    virtual EncSet do_gather(Item *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtype do_gather " << *i << " encset " << tr.encset << "\n";
        return do_gather_type((T*) i, tr, a);
    }
    virtual void do_enforce(Item *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtype do_enforce " << *i << " encset " << tr.encset << "\n";
        do_enforce_type((T*) i, tr, a);
    }
    virtual Item* do_optimize(Item *i, Analysis & a) const {
        return do_optimize_type((T*) i, a);
    }
    virtual Item* do_rewrite(Item *i, Analysis & a) const {
        return do_rewrite_type((T*) i, a);
    }
    virtual void  do_rewrite_proj(Item *i, Analysis & a, vector<Item *> &l) const {
        do_rewrite_proj_type((T*) i, a, l);
    }
    virtual void  do_rewrite_insert(Item *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const {
        do_rewrite_insert_type((T*) i, a, l, fm);
    }
 private:
    virtual EncSet do_gather_type(T *, const constraints&, Analysis & a) const = 0;
    virtual void   do_enforce_type(T *, const constraints&, Analysis & a) const = 0;
    virtual Item * do_optimize_type(T *i, Analysis & a) const {
        return do_optimize_const_item(i, a);
    }
    virtual Item * do_rewrite_type(T *i, Analysis & a) const { return i; }
    virtual void   do_rewrite_proj_type(T *i, Analysis & a, vector<Item *> &l) const {
        l.push_back(do_rewrite_type(i, a));
    }
    virtual void   do_rewrite_insert_type(T *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const {
        // default is un-implemented. we'll implement these as they come
        UNIMPLEMENTED;
    }
};

template<class T, Item::Type TYPE>
class CItemSubtypeIT : public CItemSubtype<T> {
 public:
    CItemSubtypeIT() { itemTypes.reg(TYPE, this); }
};

template<class T, Item_func::Functype TYPE>
class CItemSubtypeFT : public CItemSubtype<T> {
 public:
    CItemSubtypeFT() { funcTypes.reg(TYPE, this); }
};

template<class T, Item_sum::Sumfunctype TYPE>
class CItemSubtypeST : public CItemSubtype<T> {
 public:
    CItemSubtypeST() { sumFuncTypes.reg(TYPE, this); }
};

template<class T, const char *TYPE>
class CItemSubtypeFN : public CItemSubtype<T> {
 public:
    CItemSubtypeFN() { funcNames.reg(std::string(TYPE), this); }
};


/*
 * Actual item handlers.
 */
static void process_select_lex(st_select_lex *select_lex, const constraints &tr, Analysis & a);

static void optimize_select_lex(st_select_lex *select_lex, Analysis & a);

static void rewrite_select_lex(st_select_lex *select_lex, Analysis & a);

static class ANON : public CItemSubtypeIT<Item_field, Item::Type::FIELD_ITEM> {

    inline string extract_fieldname(Item_field *i) const
    {
        stringstream fieldtemp;
        fieldtemp << *i;
        return fieldtemp.str();
    }

    virtual EncSet do_gather_type(Item_field *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT do_gather " << *i << "\n";

        string fullfieldname = extract_fieldname(i);

        string fieldname = i->field_name;
        string table = i->table_name;

        FieldMeta * fm = a.schema->getFieldMeta(table, fieldname);

        // check compatibility for each of the constraints given
        // in the incoming enc set, either filtering them out, or
        // by modification
        OnionLevelFieldMap m;
        for (auto it = tr.encset.osl.begin();
             it != tr.encset.osl.end();
             ++it) {
            // if the field is a wildcard, then replace it with this field
            // (or if it's the same field
            if (FieldQualifies(it->second.second, fm)) {
                m[it->first] = it->second;
                m[it->first].second = fm;
            } else {
                // in the case of DET_JOIN/OPE_JOIN,
                // we take the constraint regardless of
                // field (since we can convert), and we update the
                // field to *this* field if we are lexicographically
                // ahead
                if (it->first == oDET || it->first == oOPE) {
                    m[it->first] = LevelFieldPair(
                            it->first == oDET ?
                                SECLEVEL::DETJOIN : SECLEVEL::OPEJOIN,
                            it->second.second->fname < fieldname ?
                                it->second.second : fm);
                }
            }
        }

        return EncSet(m);
    }

    virtual void
    do_enforce_type(Item_field *i, const constraints &tr, Analysis & a) const
    {
        assert(tr.encset.empty() || tr.encset.singleton());
        if (tr.encset.empty()) {
            throw runtime_error("bail out");
        }
        auto encpair = tr.encset.extract_singleton();

        string fieldname = extract_fieldname(i);
        auto it = a.fieldToAMeta.find(fieldname);
        if (it == a.fieldToAMeta.end()) {
            FieldMeta *fm = a.schema->getFieldMeta(i->table_name, i->field_name);
            if (fm) {
                // bootstrap a new FieldAMeta from the FieldMeta's encdesc
                a.fieldToAMeta[fieldname] = new FieldAMeta(fm->encdesc);
                a.itemToFieldMeta[i]      = fm;
                it = a.fieldToAMeta.find(fieldname);
            } else {
                // we aren't aware of this field. this is an error
                // for now
                cryptdb_err() << "Cannot find FieldMeta information for: " << *i;
            }
        }
        it->second->exposedLevels.restrict(encpair.first,
                                           encpair.second.first);

        cerr << "ENCSET FOR FIELD " << fieldname << " is " << a.fieldToAMeta[fieldname]->exposedLevels << "\n";
        record_item_meta_for_constraints(i, tr, a);
    }

    virtual Item *
    do_rewrite_type(Item_field *i, Analysis & a) const
    {
        auto it = a.itemHasRewrite.find(i);
        if (it == a.itemHasRewrite.end()) {
            // fix table name
            const char * table = i->table_name;
            i->table_name = make_thd_string(anonymize_table_name(i->table_name, a));
            // pick the column corresponding to the onion we want
            auto it = a.itemToMeta.find(i);
            if (it == a.itemToMeta.end()) {
                // this is a bug, we should have recorded this in enforce()
                cryptdb_err() << "should have recorded item meta object in enforce()";
            }
            ItemMeta *im = it->second;
            cerr << "onion is " << im->o << "\n";
            cerr << "table: " << table << endl;
            cerr << "i->field_name: " << i->field_name << endl;
            i->field_name = make_thd_string(get_column_name(string(table), string(i->field_name), im->o,  a));
            a.itemHasRewrite.insert(i);
        }
        return i;
    }

    inline Item_field * make_from_template(Item_field *t, const char *name) const
    {
        THD *thd = current_thd;
        assert(thd);
        // bootstrap i0 from t
        Item_field *i0 = new Item_field(thd, t);
        // clear out alias
        i0->name = NULL;
        i0->field_name = thd->strdup(name);
        return i0;
    }

    virtual void
    do_rewrite_proj_type(Item_field *i, Analysis & a, vector<Item *> &l) const
    {
	//rewrite current projection field
        l.push_back(do_rewrite_type(i, a));

        // if there is a salt for the onion, then also fetch the onion from the server
        auto it = a.itemToFieldMeta.find(i);
        assert(it != a.itemToFieldMeta.end());
        FieldMeta *fm = it->second;

	addToReturn(a.rmeta, a.pos++, a.itemToMeta[i], fm->has_salt);

	if (fm->has_salt) {
            assert(!fm->salt_name.empty());
            l.push_back(make_from_template(i, fm->salt_name.c_str()));
	    addSaltToReturn(a.rmeta, a.pos++);
        }
    }

    virtual void
    do_rewrite_insert_type(Item_field *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
        assert(fm == NULL);
        // need to map this one field into all of its onions
        // TODO: this is kind of a duplicate of rewrite_create_field(),
        // but not quite. see if we can somehow reconcile these two
        // pieces of code
        fm = a.schema->getFieldMeta(i->table_name, i->field_name);
        for (auto it = fm->onionnames.begin();
             it != fm->onionnames.end();
             ++it) {
            const string &name = it->second;
            l.push_back(make_from_template(i, name.c_str()));
        }
        if (fm->has_salt) {
            assert(!fm->salt_name.empty());
            l.push_back(make_from_template(i, fm->salt_name.c_str()));
        }
    }

} ANON;

static class ANON : public CItemSubtypeIT<Item_string, Item::Type::STRING_ITEM> {
    virtual EncSet do_gather_type(Item_string *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT const string do_gather " << *i << "\n";
        /* constant strings are always ok */
        return tr.encset;
    }
    virtual void do_enforce_type(Item_string *i, const constraints &tr, Analysis & a) const
    {
        record_item_meta_for_constraints(i, tr, a);
    }
    virtual Item * do_optimize_type(Item_string *i, Analysis & a) const {
        return i;
    }

    virtual Item * do_rewrite_type(Item_string *i, Analysis & a) const {
        string enc = encryptConstantItem(i,  a);
        return new Item_hex_string(enc.data(), enc.length());
    }

    virtual void
    do_rewrite_insert_type(Item_string *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
        assert(fm != NULL);
        String s;
        String *s0 = i->val_str(&s);

        string plaindata = string(s0->ptr(), s0->length());

        uint64_t salt = 0;
        if (fm->has_salt) {
            salt = randomValue();
        } else {
            //TODO raluca
            //need to use table salt in this case
        }

        assert(s0 != NULL);
        for (auto it = fm->onionnames.begin();
             it != fm->onionnames.end();
             ++it)
        {

            string anonName = fullName(it->second, fm->tm->anonTableName);
            bool isBin;

            string enc = a.cm->crypt(a.cm->getmkey(), plaindata, TYPE_TEXT,
                                     anonName, getMin(it->first),
                                     getMax(it->first), isBin, salt);

            l.push_back(new Item_hex_string(enc.data(), enc.length()));

        }

        if (fm->has_salt) {
            string salt_s = strFromVal(salt);
            l.push_back(new Item_hex_string(salt_s.data(), salt_s.length()));
        }

    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_num, Item::Type::INT_ITEM> {
    virtual EncSet do_gather_type(Item_num *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT num do_gather " << *i << "\n";
        /* constant ints are always ok */
        return tr.encset;
    }
    virtual void do_enforce_type(Item_num *i, const constraints &tr, Analysis & a) const
    {
        record_item_meta_for_constraints(i, tr, a);
    }
    virtual Item * do_optimize_type(Item_num *i, Analysis & a) const {
        return i;
    }
    virtual Item * do_rewrite_type(Item_num *i, Analysis & a) const {
        string enc = encryptConstantItem(i, a);
        return new Item_int((ulonglong) valFromStr(enc));
    }
    virtual void
    do_rewrite_insert_type(Item_num *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {

        //TODO: this part is quite repetitive with string or
        //any other type -- write a function

        assert(fm != NULL);
        longlong n = i->val_int();
        string plaindata = strFromVal((uint64_t)n);

        uint64_t salt = 0;
        if (fm->has_salt) {
            salt = randomValue();
        } else {
            //TODO raluca
            //need to use table salt in this case
        }


        for (auto it = fm->onionnames.begin();
             it != fm->onionnames.end();
             ++it) {
            string anonName = fullName(it->second, fm->tm->anonTableName);
            bool isBin;

            string enc = a.cm->crypt(a.cm->getmkey(), plaindata, TYPE_INTEGER,
                                     anonName, getMin(it->first),
                                     getMax(it->first), isBin, salt);

            l.push_back(new Item_int((ulonglong) valFromStr(enc)));
        }
        if (fm->has_salt) {
            l.push_back(new Item_int((ulonglong) salt));
        }
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_decimal, Item::Type::DECIMAL_ITEM> {
    virtual EncSet do_gather_type(Item_decimal *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT decimal do_gather " << *i << "\n";
        /* constant decimals are always ok */
        return tr.encset;
    }
    virtual void do_enforce_type(Item_decimal *i, const constraints &tr, Analysis & a) const
    {
        record_item_meta_for_constraints(i, tr, a);
    }
    virtual Item * do_optimize_type(Item_decimal *i, Analysis & a) const {
        return i;
    }
    virtual Item * do_rewrite_type(Item_decimal *i, Analysis & a) const {
        double n = i->val_real();
        char buf[sizeof(double) * 2];
        sprintf(buf, "%x", (unsigned int)n);
        // TODO(stephentu): Do some actual encryption of the double here
        return new Item_hex_string(buf, sizeof(buf));
    }
    virtual void
    do_rewrite_insert_type(Item_decimal *i, Analysis & a, vector<Item *> &l, FieldMeta *fm) const
    {
        assert(fm != NULL);
        double n = i->val_real();
        char buf[sizeof(double) * 2];
        sprintf(buf, "%x", (unsigned int)n);
        for (auto it = fm->onionnames.begin();
             it != fm->onionnames.end();
             ++it) {
            l.push_back(new Item_hex_string(buf, sizeof(buf)));
        }
        if (fm->has_salt) {
            l.push_back(new Item_hex_string(buf, sizeof(buf)));
        }
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_neg, Item_func::Functype::NEG_FUNC> {
    virtual EncSet do_gather_type(Item_func_neg *i, const constraints &tr, Analysis & a) const {
        return gather(i->arguments()[0], tr, a);
    }
    virtual void do_enforce_type(Item_func_neg *i, const constraints &tr, Analysis & a) const {
        enforce(i->arguments()[0], tr, a);
    }
    virtual Item * do_optimize_type(Item_func_neg *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_not, Item_func::Functype::NOT_FUNC> {
    virtual EncSet do_gather_type(Item_func_not *i, const constraints &tr, Analysis & a) const {
        return gather(i->arguments()[0], tr, a);
    }
    virtual void do_enforce_type(Item_func_not *i, const constraints &tr, Analysis & a) const {
        enforce(i->arguments()[0], tr, a);
    }
    virtual Item * do_optimize_type(Item_func_not *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_subselect, Item::Type::SUBSELECT_ITEM> {
    virtual EncSet do_gather_type(Item_subselect *i, const constraints &tr, Analysis & a) const {
        st_select_lex *select_lex = i->get_select_lex();
        process_select_lex(select_lex, tr, a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_subselect *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_subselect *i, Analysis & a) const {
        optimize_select_lex(i->get_select_lex(), a);
        return i;
    }
} ANON;

extern const char str_in_optimizer[] = "<in_optimizer>";
static class ANON : public CItemSubtypeFN<Item_in_optimizer, str_in_optimizer> {
    virtual EncSet do_gather_type(Item_in_optimizer *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeFN do_gather " << *i << "\n";

        Item **args = i->arguments();
        analyze(args[0], constraints(EMPTY_EncSet, "in_opt", i, &tr), a);
        analyze(args[1], constraints(EMPTY_EncSet, "in_opt", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_in_optimizer *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_in_optimizer *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_cache, Item::Type::CACHE_ITEM> {
    virtual EncSet do_gather_type(Item_cache *i, const constraints &tr, Analysis & a) const {
        Item *example = (*i).*rob<Item_cache, Item*, &Item_cache::example>::ptr();
        if (example)
            return gather(example, tr, a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_cache *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_cache *i, Analysis & a) const {
        // TODO(stephentu): figure out how to use rob here
        return i;
    }
} ANON;

template<Item_func::Functype FT, class IT>
class CItemCompare : public CItemSubtypeFT<Item_func, FT> {
    virtual EncSet do_gather_type(Item_func *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemCompare do_gather func " << *i << "\n";

        EncSet t2;

        if (FT == Item_func::Functype::EQ_FUNC ||
            FT == Item_func::Functype::EQUAL_FUNC ||
            FT == Item_func::Functype::NE_FUNC) {
            t2 = EQ_EncSet;
        } else {
            t2 = ORD_EncSet;
        }

        Item **args = i->arguments();
        const char *reason = "compare_func";
        if (!args[0]->const_item() && !args[1]->const_item())
            reason = "compare_func_join";

        EncSet new_encset = tr.encset.intersect(t2);
        //cerr << "intersect " << tr << " with " << t2 << " result is " << new_encset << " \n";

        if (new_encset.osl.size() == 0) {
            cerr << "query not supported because " << reason << " and " << tr << "\n";
            exit(-1);//TODO: throw some exception
        }

        new_encset = gather(args[0], constraints(new_encset, reason, i, &tr), a);
        return gather(args[1], constraints(new_encset, reason, i, &tr), a);
    }
    virtual void do_enforce_type(Item_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        const char *reason = "compare_func";
        if (!args[0]->const_item() && !args[1]->const_item())
            reason = "compare_func_join";
        enforce(args[0], constraints(tr.encset, reason, i, &tr), a);
        enforce(args[1], constraints(tr.encset, reason, i, &tr), a);
    }
    virtual Item * do_optimize_type(Item_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
    virtual Item * do_rewrite_type(Item_func *i, Analysis & a) const {
        return do_rewrite_type_args(i, a);
    }
};

static CItemCompare<Item_func::Functype::EQ_FUNC,    Item_func_eq>    ANON;
static CItemCompare<Item_func::Functype::EQUAL_FUNC, Item_func_equal> ANON;
static CItemCompare<Item_func::Functype::NE_FUNC,    Item_func_ne>    ANON;
static CItemCompare<Item_func::Functype::GT_FUNC,    Item_func_gt>    ANON;
static CItemCompare<Item_func::Functype::GE_FUNC,    Item_func_ge>    ANON;
static CItemCompare<Item_func::Functype::LT_FUNC,    Item_func_lt>    ANON;
static CItemCompare<Item_func::Functype::LE_FUNC,    Item_func_le>    ANON;

template<Item_func::Functype FT, class IT>
class CItemCond : public CItemSubtypeFT<Item_cond, FT> {
    virtual EncSet do_gather_type(Item_cond *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemCond do_gather " << *i << "\n";
        //cerr << "do_a_t item_cond reason " << tr << "\n";
        auto it = List_iterator<Item>(*i->argument_list());
        //we split the current item in the different subexpressions
        for (;;) {
            Item *argitem = it++;
            if (!argitem)
                break;
            analyze(argitem, constraints(tr.encset, "cond", i, &tr), a);
        }
        return tr.encset;
    }
    virtual void do_enforce_type(Item_cond *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_cond *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
    virtual Item * do_rewrite_type(Item_cond *i, Analysis & a) const {
        auto item_it = List_iterator<Item>(*i->argument_list());
        for (;;) {
            if (!item_it++)
                break;
            rewrite(item_it.ref(), a);
        }
        return i;
    }
};

static CItemCond<Item_func::Functype::COND_AND_FUNC, Item_cond_and> ANON;
static CItemCond<Item_func::Functype::COND_OR_FUNC,  Item_cond_or>  ANON;

template<Item_func::Functype FT>
class CItemNullcheck : public CItemSubtypeFT<Item_bool_func, FT> {
    virtual EncSet do_gather_type(Item_bool_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet,  "nullcheck", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_bool_func *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_bool_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

static CItemNullcheck<Item_func::Functype::ISNULL_FUNC> ANON;
static CItemNullcheck<Item_func::Functype::ISNOTNULL_FUNC> ANON;

static class ANON : public CItemSubtypeFT<Item_func_get_system_var, Item_func::Functype::GSYSVAR_FUNC> {
    virtual EncSet do_gather_type(Item_func_get_system_var *i, const constraints &tr, Analysis & a) const {
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_get_system_var *i, const constraints &tr, Analysis & a) const
    {}
} ANON;

// This is a bit of a hack: until our embedded DB actually has these UDFs for
// hom-add, then we will just lie about its existence. Eventually we could
// probably pull the udf_func object out of the embedded db.

static LEX_STRING s_HomAdd = {
        (char*)"hom_add",
        sizeof("hom_add"),
    };

static udf_func s_HomAddUdfFunc = {
        s_HomAdd,
        STRING_RESULT,
        UDFTYPE_FUNCTION,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        0L,
    };

static LEX_STRING s_HomSub = {
        (char*)"hom_sub",
        sizeof("hom_sub"),
    };

static udf_func s_HomSubUdfFunc = {
        s_HomSub,
        STRING_RESULT,
        UDFTYPE_FUNCTION,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        0L,
    };

template<const char *NAME>
class CItemAdditive : public CItemSubtypeFN<Item_func_additive_op, NAME> {
    virtual EncSet do_gather_type(Item_func_additive_op *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        assert(i->argument_count() == 2);
        EncSet cur = tr.encset.intersect(ADD_EncSet);
        cur = gather(args[0], constraints(cur, "additive", i, &tr), a);
        return gather(args[1], constraints(cur, "additive", i, &tr), a);
    }
    virtual void do_enforce_type(Item_func_additive_op *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        enforce(args[0], constraints(tr.encset, "additive", i, &tr), a);
        enforce(args[1], constraints(tr.encset, "additive", i, &tr), a);
    }
    virtual Item * do_optimize_type(Item_func_additive_op *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
    virtual Item * do_rewrite_type(Item_func_additive_op *i, Analysis & a) const {
        // rewrite children
        do_rewrite_type_args(i, a);

        List<Item> l;
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            l.push_back(args[x]);
        }

        // replace with hom_(add/sub)
        return strcmp(NAME, "+") == 0 ?
            new Item_func_udf_str(&s_HomAddUdfFunc, l) :
            new Item_func_udf_str(&s_HomSubUdfFunc, l) ;
    }
};

extern const char str_plus[] = "+";
static CItemAdditive<str_plus> ANON;

extern const char str_minus[] = "-";
static CItemAdditive<str_minus> ANON;

template<const char *NAME>
class CItemMath : public CItemSubtypeFN<Item_func, NAME> {
    virtual EncSet do_gather_type(Item_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet, "math", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_mul[] = "*";
static CItemMath<str_mul> ANON;

extern const char str_div[] = "/";
static CItemMath<str_div> ANON;

extern const char str_idiv[] = "div";
static CItemMath<str_idiv> ANON;

extern const char str_sqrt[] = "sqrt";
static CItemMath<str_sqrt> ANON;

extern const char str_round[] = "round";
static CItemMath<str_round> ANON;

extern const char str_sin[] = "sin";
static CItemMath<str_sin> ANON;

extern const char str_cos[] = "cos";
static CItemMath<str_cos> ANON;

extern const char str_acos[] = "acos";
static CItemMath<str_acos> ANON;

extern const char str_pow[] = "pow";
static CItemMath<str_pow> ANON;

extern const char str_log[] = "log";
static CItemMath<str_log> ANON;

extern const char str_radians[] = "radians";
static CItemMath<str_radians> ANON;

extern const char str_if[] = "if";
static class ANON : public CItemSubtypeFN<Item_func_if, str_if> {
    virtual EncSet do_gather_type(Item_func_if *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        assert(i->argument_count() == 3);
        analyze(args[0], constraints(tr.encset, "if_cond", i, &tr), a);
        analyze(args[1], constraints(tr.encset, "true_branch", i, &tr), a);
        analyze(args[2], constraints(tr.encset, "false_branch", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_if *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_if *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

extern const char str_nullif[] = "nullif";
static class ANON : public CItemSubtypeFN<Item_func_nullif, str_nullif> {
    virtual EncSet do_gather_type(Item_func_nullif *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        EncSet cur = EQ_EncSet;
        for (uint x = 0; x < i->argument_count(); x++)
            cur = gather(args[x], constraints(cur, "nullif", i, &tr), a);
        return cur;
    }
    virtual void do_enforce_type(Item_func_nullif *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            enforce(args[x], constraints(tr.encset, "nullif", i, &tr), a);
    }
    virtual Item * do_optimize_type(Item_func_nullif *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

extern const char str_coalesce[] = "coalesce";
static class ANON : public CItemSubtypeFN<Item_func_coalesce, str_coalesce> {
    virtual EncSet do_gather_type(Item_func_coalesce *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], tr, a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_coalesce *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_coalesce *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

extern const char str_case[] = "case";
static class ANON : public CItemSubtypeFN<Item_func_case, str_case> {
    virtual EncSet do_gather_type(Item_func_case *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        int first_expr_num = (*i).*rob<Item_func_case, int,
                &Item_func_case::first_expr_num>::ptr();
        int else_expr_num = (*i).*rob<Item_func_case, int,
                &Item_func_case::else_expr_num>::ptr();
        uint ncases = (*i).*rob<Item_func_case, uint,
                &Item_func_case::ncases>::ptr();

        if (first_expr_num >= 0)
            analyze(args[first_expr_num],
                constraints(EQ_EncSet, "case_first", i, &tr), a);
        if (else_expr_num >= 0)
            analyze(args[else_expr_num], tr, a);

        for (uint x = 0; x < ncases; x += 2) {
            if (first_expr_num < 0)
            analyze(args[x],
                constraints(EMPTY_EncSet, "case_nofirst", i, &tr), a);
            else
            analyze(args[x],
                constraints(EQ_EncSet, "case_w/first", i, &tr), a);
            analyze(args[x+1], tr, a);
        }
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_case *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_case *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *NAME>
class CItemStrconv : public CItemSubtypeFN<Item_str_conv, NAME> {
    virtual EncSet do_gather_type(Item_str_conv *i, const constraints & tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet, "strconv", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_str_conv *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_str_conv *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_lcase[] = "lcase";
static CItemStrconv<str_lcase> ANON;

extern const char str_ucase[] = "ucase";
static CItemStrconv<str_ucase> ANON;

extern const char str_length[] = "length";
static CItemStrconv<str_length> ANON;

extern const char str_char_length[] = "char_length";
static CItemStrconv<str_char_length> ANON;

extern const char str_substr[] = "substr";
static CItemStrconv<str_substr> ANON;

extern const char str_concat[] = "concat";
static CItemStrconv<str_concat> ANON;

extern const char str_concat_ws[] = "concat_ws";
static CItemStrconv<str_concat_ws> ANON;

extern const char str_md5[] = "md5";
static CItemStrconv<str_md5> ANON;

extern const char str_left[] = "left";
static CItemStrconv<str_left> ANON;

extern const char str_regexp[] = "regexp";
static CItemStrconv<str_regexp> ANON;

template<const char *NAME>
class CItemLeafFunc : public CItemSubtypeFN<Item_func, NAME> {
    virtual EncSet do_gather_type(Item_func *i, const constraints &tr, Analysis & a) const {
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func *i, const constraints &tr, Analysis & a) const
    {}
};

extern const char str_found_rows[] = "found_rows";
static CItemLeafFunc<str_found_rows> ANON;

extern const char str_last_insert_id[] = "last_insert_id";
static CItemLeafFunc<str_last_insert_id> ANON;

extern const char str_rand[] = "rand";
static CItemLeafFunc<str_rand> ANON;

static class ANON : public CItemSubtypeFT<Item_extract, Item_func::Functype::EXTRACT_FUNC> {
    virtual EncSet do_gather_type(Item_extract *i, const constraints &tr, Analysis & a) const {
        analyze(i->arguments()[0], constraints(EMPTY_EncSet, "extract", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_extract *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_extract *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *NAME>
class CItemDateExtractFunc : public CItemSubtypeFN<Item_int_func, NAME> {
    virtual EncSet do_gather_type(Item_int_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            /* assuming we separately store different date components */
            analyze(args[x], tr, a);
        }
        return tr.encset;
    }
    virtual void do_enforce_type(Item_int_func *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_int_func *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_second[] = "second";
static CItemDateExtractFunc<str_second> ANON;

extern const char str_minute[] = "minute";
static CItemDateExtractFunc<str_minute> ANON;

extern const char str_hour[] = "hour";
static CItemDateExtractFunc<str_hour> ANON;

extern const char str_to_days[] = "to_days";
static CItemDateExtractFunc<str_to_days> ANON;

extern const char str_year[] = "year";
static CItemDateExtractFunc<str_year> ANON;

extern const char str_month[] = "month";
static CItemDateExtractFunc<str_month> ANON;

extern const char str_dayofmonth[] = "dayofmonth";
static CItemDateExtractFunc<str_dayofmonth> ANON;

extern const char str_unix_timestamp[] = "unix_timestamp";
static CItemDateExtractFunc<str_unix_timestamp> ANON;

extern const char str_date_add_interval[] = "date_add_interval";
static class ANON : public CItemSubtypeFN<Item_date_add_interval, str_date_add_interval> {
    virtual EncSet do_gather_type(Item_date_add_interval *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            /* XXX perhaps too conservative */
            analyze(args[x], constraints(EMPTY_EncSet, "date_add", i, &tr), a);
        }
        return tr.encset;
    }
    virtual void do_enforce_type(Item_date_add_interval *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_date_add_interval *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *NAME>
class CItemDateNow : public CItemSubtypeFN<Item_func_now, NAME> {
    virtual EncSet do_gather_type(Item_func_now *i, const constraints &tr, Analysis & a) const {
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_now *i, const constraints &tr, Analysis & a) const
    {}
};

extern const char str_now[] = "now";
static CItemDateNow<str_now> ANON;

extern const char str_utc_timestamp[] = "utc_timestamp";
static CItemDateNow<str_utc_timestamp> ANON;

extern const char str_sysdate[] = "sysdate";
static CItemDateNow<str_sysdate> ANON;

template<const char *NAME>
class CItemBitfunc : public CItemSubtypeFN<Item_func_bit, NAME> {
    virtual EncSet do_gather_type(Item_func_bit *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet, "bitfunc", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_bit *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_bit *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_bit_not[] = "~";
static CItemBitfunc<str_bit_not> ANON;

extern const char str_bit_or[] = "|";
static CItemBitfunc<str_bit_or> ANON;

extern const char str_bit_xor[] = "^";
static CItemBitfunc<str_bit_xor> ANON;

extern const char str_bit_and[] = "&";
static CItemBitfunc<str_bit_and> ANON;

static class ANON : public CItemSubtypeFT<Item_func_like, Item_func::Functype::LIKE_FUNC> {
    virtual EncSet do_gather_type(Item_func_like *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        if (args[1]->type() == Item::Type::STRING_ITEM) {
            string s(args[1]->str_value.ptr(), args[1]->str_value.length());
            if (s.find('%') == s.npos && s.find('_') == s.npos) {
                /* some queries actually use LIKE as an equality check.. */
                analyze(args[0], constraints(EQ_EncSet, "like-eq", i, &tr), a);
            } else {
                /* XXX check if pattern is one we can support? */
                stringstream ss;
                ss << "like:'" << s << "'";
                analyze(args[0], constraints(Search_EncSet, ss.str(), i, &tr), a);
            }
        } else {
            /* we cannot support non-constant search patterns */
            for (uint x = 0; x < i->argument_count(); x++)
                analyze(args[x], constraints(EMPTY_EncSet, "like-non-const", i, &tr), a);
        }
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_like *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_like *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func, Item_func::Functype::FUNC_SP> {
    void error(Item_func *i) const __attribute__((noreturn)) {
        thrower() << "unsupported store procedure call " << *i;
    }

    virtual EncSet do_gather_type(Item_func *i, const constraints &tr, Analysis & a) const __attribute__((noreturn)) { error(i); }
    virtual void do_enforce_type(Item_func *i, const constraints &tr, Analysis & a) const __attribute__((noreturn))
    { error(i); }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_in, Item_func::Functype::IN_FUNC> {
    virtual EncSet do_gather_type(Item_func_in *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EQ_EncSet, "in", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_in *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_in *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_in, Item_func::Functype::BETWEEN> {
    virtual EncSet do_gather_type(Item_func_in *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(ORD_EncSet, "between", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_in *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_in *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<const char *FN>
class CItemMinMax : public CItemSubtypeFN<Item_func_min_max, FN> {
    virtual EncSet do_gather_type(Item_func_min_max *i, const constraints &tr, Analysis & a) const {
        //cerr << "do_a_t Item_fuc_min_max reason " << tr << "\n";
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(ORD_EncSet, "min/max", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_min_max *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_min_max *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
};

extern const char str_greatest[] = "greatest";
static CItemMinMax<str_greatest> ANON;

extern const char str_least[] = "least";
static CItemMinMax<str_least> ANON;

extern const char str_strcmp[] = "strcmp";
static class ANON : public CItemSubtypeFN<Item_func_strcmp, str_strcmp> {
    virtual EncSet do_gather_type(Item_func_strcmp *i, const constraints &tr, Analysis & a) const {
        //cerr << "do_a_t Item_func_strcmp reason " << tr << "\n";
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EQ_EncSet, "strcmp", i, &tr), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_strcmp *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_strcmp *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

template<Item_sum::Sumfunctype SFT>
class CItemCount : public CItemSubtypeST<Item_sum_count, SFT> {
    virtual EncSet do_gather_type(Item_sum_count *i, const constraints &tr, Analysis & a) const {
        //cerr << "do_a_t Item_sum_count reason " << tr << "\n";
        if (i->has_with_distinct())
            analyze(i->get_arg(0), constraints(EQ_EncSet, "count distinct", i, &tr, false), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_sum_count *i, const constraints &tr, Analysis & a) const
    {}
};

static CItemCount<Item_sum::Sumfunctype::COUNT_FUNC> ANON;
static CItemCount<Item_sum::Sumfunctype::COUNT_DISTINCT_FUNC> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemChooseOrder : public CItemSubtypeST<Item_sum_hybrid, SFT> {
    virtual EncSet do_gather_type(Item_sum_hybrid *i, const constraints &tr, Analysis & a) const {
        //cerr << "do_a_t Item_sum_hybrid reason " << tr << "\n";
        analyze(i->get_arg(0), constraints(ORD_EncSet, "min/max_agg", i, &tr, false), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_sum_hybrid *i, const constraints &tr, Analysis & a) const
    {}
};

static CItemChooseOrder<Item_sum::Sumfunctype::MIN_FUNC> ANON;
static CItemChooseOrder<Item_sum::Sumfunctype::MAX_FUNC> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemSum : public CItemSubtypeST<Item_sum_sum, SFT> {
    virtual EncSet do_gather_type(Item_sum_sum *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_sum_sum reason " << tr  << "\n";
        if (i->has_with_distinct())
            analyze(i->get_arg(0), constraints(EQ_EncSet, "agg_distinct", i, &tr, false), a);

        analyze(i->get_arg(0), constraints(tr.encset.intersect(ADD_EncSet), "sum/avg", i, &tr, false), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_sum_sum *i, const constraints &tr, Analysis & a) const
    {}
};

static CItemSum<Item_sum::Sumfunctype::SUM_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::SUM_DISTINCT_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::AVG_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::AVG_DISTINCT_FUNC> ANON;

static class ANON : public CItemSubtypeST<Item_sum_bit, Item_sum::Sumfunctype::SUM_BIT_FUNC> {
    virtual EncSet do_gather_type(Item_sum_bit *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_sum_bit reason " << tr << "\n";
        analyze(i->get_arg(0), constraints(EMPTY_EncSet, "bitagg", i, &tr, false), a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_sum_bit *i, const constraints &tr, Analysis & a) const
    {}
} ANON;

static class ANON : public CItemSubtypeST<Item_func_group_concat, Item_sum::Sumfunctype::GROUP_CONCAT_FUNC> {
    virtual EncSet do_gather_type(Item_func_group_concat *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_func_group reason " << tr << "\n";
        uint arg_count_field = (*i).*rob<Item_func_group_concat, uint,
                &Item_func_group_concat::arg_count_field>::ptr();
        for (uint x = 0; x < arg_count_field; x++) {
            /* XXX could perform in the proxy.. */
            analyze(i->get_arg(x), constraints(EMPTY_EncSet, "group_concat", i, &tr), a);
        }

        /* XXX order, unused in trace queries.. */
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_group_concat *i, const constraints &tr, Analysis & a) const
    {}
    // TODO(stephentu): figure out how to rob the arg fields for optimization
} ANON;

static class ANON : public CItemSubtypeFT<Item_char_typecast, Item_func::Functype::CHAR_TYPECAST_FUNC> {
    virtual EncSet do_gather_type(Item_char_typecast *i, const constraints &tr, Analysis & a) const {
        thrower() << "what does Item_char_typecast do?";
        UNIMPLEMENTED;
    }
    virtual void do_enforce_type(Item_char_typecast *i, const constraints &tr, Analysis & a) const
    {}
} ANON;

extern const char str_cast_as_signed[] = "cast_as_signed";
static class ANON : public CItemSubtypeFN<Item_func_signed, str_cast_as_signed> {
    virtual EncSet do_gather_type(Item_func_signed *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_func_signed reason " << tr << "\n";
        analyze(i->arguments()[0], tr, a);
        return tr.encset;
    }
    virtual void do_enforce_type(Item_func_signed *i, const constraints &tr, Analysis & a) const
    {}
    virtual Item * do_optimize_type(Item_func_signed *i, Analysis & a) const {
        return do_optimize_type_self_and_args(i, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_ref, Item::Type::REF_ITEM> {
    virtual EncSet do_gather_type(Item_ref *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_ref reason " << tr << "\n";
        if (i->ref) {
            analyze(*i->ref, tr, a);
            return tr.encset;
        } else {
            thrower() << "how to resolve Item_ref::ref?";
            UNIMPLEMENTED;
        }
    }
    virtual void do_enforce_type(Item_ref *i, const constraints &tr, Analysis & a) const
    {}
} ANON;


/*
 * Some helper functions.
 */

static void
optimize_select_lex(st_select_lex *select_lex, Analysis & a)
{
    auto item_it = List_iterator<Item>(select_lex->item_list);
    for (;;) {
        if (!item_it++)
            break;
        optimize(item_it.ref(), a);
    }

    if (select_lex->where)
        optimize(&select_lex->where, a);

    if (select_lex->join &&
        select_lex->join->conds &&
        select_lex->where != select_lex->join->conds)
        optimize(&select_lex->join->conds, a);

    if (select_lex->having)
        optimize(&select_lex->having, a);

    for (ORDER *o = select_lex->group_list.first; o; o = o->next)
        optimize(o->item, a);

    for (ORDER *o = select_lex->order_list.first; o; o = o->next)
        optimize(o->item, a);
}

static void
process_select_lex(st_select_lex *select_lex, const constraints &tr, Analysis & a)
{
    cerr << "in process select lex \n";
    //select clause
    auto item_it = List_iterator<Item>(select_lex->item_list);
    for (;;) {
        Item *item = item_it++;
        if (!item)
            break;

        analyze(item, tr, a);
    }

    if (select_lex->where)
        analyze(select_lex->where, constraints(FULL_EncSet, "where", select_lex->where, 0), a);

    // TODO(stephentu): I'm not sure if we can ever have a
    // select_lex->where != select_lex->join->conds, but
    // it is not clear to me why this branch should execute
    // in the case where select_lex->where = select_lex->join->conds, and
    // it breaks the assumption (at least in re-write) that there will be
    // exactly one pass per item.
    //
    // I'm leaving this like so for now. Feel free to resolve it as fit
    if (select_lex->join &&
        select_lex->join->conds &&
        select_lex->where != select_lex->join->conds)
        analyze(select_lex->join->conds, constraints(FULL_EncSet, "join->conds", select_lex->join->conds, 0), a);

    if (select_lex->having)
        analyze(select_lex->having, constraints(FULL_EncSet, "having", select_lex->having, 0), a);

    for (ORDER *o = select_lex->group_list.first; o; o = o->next)
        analyze(*o->item, constraints(EQ_EncSet, "group", *o->item, 0), a);

    for (ORDER *o = select_lex->order_list.first; o; o = o->next)
        analyze(*o->item, constraints(ORD_EncSet,
                          "order", *o->item, 0, select_lex->select_limit ? false : true), a);
}

// TODO: template this
static void
rewrite_select_lex(st_select_lex *select_lex, Analysis & a)
{
    auto item_it = List_iterator<Item>(select_lex->item_list);

    List<Item> newList;
    for (;;) {
        Item *item = item_it++;
        if (!item)
            break;
        vector<Item *> l;
        itemTypes.do_rewrite_proj(item, a, l);
        for (auto it = l.begin(); it != l.end(); ++it) {
            (*it)->name = NULL; // TODO: fix this
            newList.push_back(*it);
        }
    }

    // TODO(stephentu): investigate whether or not this is a memory leak
    select_lex->item_list = newList;

    if (select_lex->where)
        rewrite(&select_lex->where, a);

    if (select_lex->join &&
        select_lex->join->conds &&
        select_lex->where != select_lex->join->conds)
        rewrite(&select_lex->join->conds, a);

    if (select_lex->having)
        rewrite(&select_lex->having, a);

    for (ORDER *o = select_lex->group_list.first; o; o = o->next)
        rewrite(o->item, a);

    for (ORDER *o = select_lex->order_list.first; o; o = o->next)
        rewrite(o->item, a);
}

static void
optimize_table_list(List<TABLE_LIST> *tll, Analysis &a)
{
    List_iterator<TABLE_LIST> join_it(*tll);
    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t)
            break;

        if (t->nested_join) {
            optimize_table_list(&t->nested_join->join_list, a);
            return;
        }

        if (t->on_expr)
            optimize(&t->on_expr, a);

        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            optimize_select_lex(u->first_select(), a);
        }
    }
}

static void
process_table_list(List<TABLE_LIST> *tll, Analysis & a)
{
    /*
     * later, need to rewrite different joins, e.g.
     * SELECT g2_ChildEntity.g_id, IF(ai0.g_id IS NULL, 1, 0) AS albumsFirst, g2_Item.g_originationTimestamp FROM g2_ChildEntity LEFT JOIN g2_AlbumItem AS ai0 ON g2_ChildEntity.g_id = ai0.g_id INNER JOIN g2_Item ON g2_ChildEntity.g_id = g2_Item.g_id INNER JOIN g2_AccessSubscriberMap ON g2_ChildEntity.g_id = g2_AccessSubscriberMap.g_itemId ...
     */

    List_iterator<TABLE_LIST> join_it(*tll);
    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t)
            break;

        if (t->nested_join) {
            process_table_list(&t->nested_join->join_list, a);
            return;
        }

        if (t->on_expr)
            analyze(t->on_expr, constraints(EMPTY_EncSet, "join_cond", t->on_expr, 0), a);

        //std::string db(t->db, t->db_length);
        //std::string table_name(t->table_name, t->table_name_length);
        //std::string alias(t->alias);

        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            /*
             * Not quite right, in terms of softness:
             * should really come from the items that eventually
             * reference columns in this derived table.
             */

            process_select_lex(u->first_select(), constraints(EMPTY_EncSet,  "sub-select", 0, 0, false), a);
        }
    }
}

static inline void
rewrite_table_list(TABLE_LIST *t, Analysis &a)
{
    string anon_name = anonymize_table_name(string(t->table_name,
                                                   t->table_name_length), a);
    t->table_name = make_thd_string(anon_name, &t->table_name_length);
    // TODO: handle correctly
    t->alias      = make_thd_string(anon_name);
}

static void
rewrite_table_list(List<TABLE_LIST> *tll, Analysis & a)
{

    List_iterator<TABLE_LIST> join_it(*tll);
    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t)
            break;

        rewrite_table_list(t, a);

        if (t->nested_join) {
            rewrite_table_list(&t->nested_join->join_list, a);
            return;
        }

        if (t->on_expr)
            rewrite(&t->on_expr, a);

        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            rewrite_select_lex(u->first_select(), a);
        }
    }
}

static void
add_table(SchemaInfo * schema, const string & table, LEX *lex) {
    assert(lex->sql_command == SQLCOM_CREATE_TABLE);

    auto it = schema->tableMetaMap.find(table);
    if (it != schema->tableMetaMap.end()) {
        // we already hold the in mem data structure representing this
        // table.
        //
        // if this isn't a create table if not exists, then issue a
        // warning and quit
        if (!(lex->create_info.options & HA_LEX_CREATE_IF_NOT_EXISTS)) {
            cerr << "ERROR: Embedded DB possibly"
                    "out of sync with regular DB (or, just programmer error)"
                 << endl;
        }
        return;
    }

    TableMeta *tm = new TableMeta();
    schema->tableMetaMap[table] = tm;

    tm->tableNo = schema->totalTables++;
    tm->anonTableName = anonymizeTableName(tm->tableNo, table, false);

    unsigned int index =  0;
    for (auto it = List_iterator<Create_field>(lex->alter_info.create_list);;) {
        Create_field * field = it++;
        if (!field) {
            break;
        }
        FieldMeta * fm = new FieldMeta();

        fm->tm        = tm;
        fm->sql_field = field->clone(current_thd->mem_root);

        fm->fname = string(fm->sql_field->field_name);

        // certain field types cannot have certain onions. for instance,
        // AGG makes no sense for non numeric types
        if (IsMySQLTypeNumeric(field->sql_type)) {
            fm->encdesc = NUMERIC_EncDec;
        } else {
            fm->encdesc = EQ_SEARCH_EncDesc;
        }

        for (auto pr : fm->encdesc.olm) {
            fm->onionnames[pr.first] = anonymizeFieldName(index, pr.first, fm->fname, false);
        }

        fm->has_salt = true;
        fm->salt_name = getFieldSalt(index, tm->anonTableName);

        assert(tm->fieldMetaMap.find(fm->fname) == tm->fieldMetaMap.end());
        tm->fieldMetaMap[fm->fname] = fm;
        tm->fieldNames.push_back(fm->fname);

        index++;

    }
}

class OnionFieldHandler {
private:
    int                   field_length;
    enum enum_field_types type;
    CHARSET_INFO *        charset;
public:
    OnionFieldHandler(enum enum_field_types t) :
        field_length(-1), type(t), charset(NULL) {}
    OnionFieldHandler(enum enum_field_types t, size_t f) :
        field_length((int)f), type(t), charset(NULL) {}
    OnionFieldHandler(enum enum_field_types t,
                      size_t f,
                      CHARSET_INFO *charset) :
        field_length((int)f), type(t), charset(charset) {}

    Create_field*
    newOnionCreateField(const char * anon_name,
                        const Create_field *f) const {
        THD *thd = current_thd;
        Create_field *f0 = f->clone(thd->mem_root);
        f0->field_name = thd->strdup(anon_name);
        if (field_length != -1) {
            f0->length = field_length;
        }
        f0->sql_type = type;
        if (charset != NULL) {
            f0->charset = charset;
        }
        return f0;
    }
};

typedef set< enum enum_field_types >   S;
typedef pair< S, OnionFieldHandler * > H;
typedef vector< H >                    V;

// TODO: this list is incomplete
const map<onion, V> OnionHandlers = {
    {oDET, V({H(S({MYSQL_TYPE_LONG,
                   MYSQL_TYPE_INT24}),
                new OnionFieldHandler(MYSQL_TYPE_LONGLONG)),
              H(S({MYSQL_TYPE_DECIMAL,
                   MYSQL_TYPE_DOUBLE,
                   MYSQL_TYPE_VARCHAR,
                   MYSQL_TYPE_BLOB}),
                new OnionFieldHandler(MYSQL_TYPE_BLOB))})},

    {oOPE, V({H(S({MYSQL_TYPE_LONG,
                   MYSQL_TYPE_INT24}),
                new OnionFieldHandler(MYSQL_TYPE_LONGLONG)),
              H(S({MYSQL_TYPE_DECIMAL,
                   MYSQL_TYPE_DOUBLE,
                   MYSQL_TYPE_VARCHAR,
                   MYSQL_TYPE_BLOB}),
                new OnionFieldHandler(MYSQL_TYPE_BLOB))})},

    {oAGG, V({H(S({MYSQL_TYPE_LONG,
                   MYSQL_TYPE_INT24,
                   MYSQL_TYPE_DECIMAL,
                   MYSQL_TYPE_DOUBLE}),
		    new OnionFieldHandler(MYSQL_TYPE_VARCHAR, 256, &my_charset_bin))})},

    {oSWP, V({H(S({MYSQL_TYPE_VARCHAR,
                   MYSQL_TYPE_BLOB}),
                new OnionFieldHandler(MYSQL_TYPE_BLOB))})},
};

static void rewrite_create_field(const string &table_name,
                                 Create_field *f,
                                 Analysis &a,
                                 vector<Create_field *> &l)
{
    FieldMeta *fm = a.schema->getFieldMeta(table_name, f->field_name);

    // create each onion column
    for (auto it = fm->onionnames.begin();
         it != fm->onionnames.end();
         ++it) {
        auto it_h = OnionHandlers.find(it->first);
        assert(it_h != OnionHandlers.end());
        auto v = it_h->second;
        Create_field *newF = NULL;
        for (auto h : v) {
            auto s = h.first;
            if (s.find(f->sql_type) != s.end()) {
                newF = h.second->newOnionCreateField(
                        it->second.c_str(), f);
                break;
            }
        }
        if (newF == NULL) {
            cryptdb_err() << "Could not rewrite for onion: " <<
                        it->first << ", type: " << f->sql_type;
        }
        l.push_back(newF);
    }

    // create salt column
    if (fm->has_salt) {
        assert(!fm->salt_name.empty());
        THD *thd         = current_thd;
        Create_field *f0 = f->clone(thd->mem_root);
        f0->field_name   = thd->strdup(fm->salt_name.c_str());
        f0->sql_type     = MYSQL_TYPE_VARCHAR;
        f0->charset      = &my_charset_bin;
        f0->length       = 8;
        l.push_back(f0);
    }
}

static void rewrite_key(const string &table_name,
                        Key *k,
                        Analysis &a,
                        vector<Key*> &l)
{
    cryptdb_err() << "No support for rewriting keys. "
            << "If you see this, please implement me";
}

/*
 * Analyzes create query.
 * Updates encrypted schema info.
 *
 */
static void
process_create_lex(LEX * lex, Analysis & a)
{
    const string &table =
        lex->select_lex.table_list.first->table_name;
    add_table(a.schema, table, lex);
}

static void
rewrite_table_list(SQL_I_List<TABLE_LIST> *tlist, Analysis &a)
{
    TABLE_LIST *tbl = tlist->first;
    for (; tbl; tbl = tbl->next_local) {
        rewrite_table_list(tbl, a);
    }
}

static void
rewrite_create_lex(LEX *lex, Analysis &a)
{
    // table name
    const string &table =
        lex->select_lex.table_list.first->table_name;

    rewrite_table_list(&lex->select_lex.table_list, a);

    //TODO: support for "create table like"
    if (lex->create_info.options & HA_LEX_CREATE_TABLE_LIKE) {
        cryptdb_err() << "No support for create table like yet. " <<
                   "If you see this, please implement me";
    } else {
        // TODO(stephentu): template this pattern away
        // (borrowed from rewrite_select_lex())
        auto cl_it = List_iterator<Create_field>(lex->alter_info.create_list);
        List<Create_field> newList;
        for (;;) {
            Create_field *cf = cl_it++;
            if (!cf)
                break;
            vector<Create_field *> l;
            rewrite_create_field(table, cf, a, l);
            for (auto it = l.begin(); it != l.end(); ++it) {
                newList.push_back(*it);
            }
        }
        lex->alter_info.create_list = newList;

        auto k_it = List_iterator<Key>(lex->alter_info.key_list);
        List<Key> newList0;
        for (;;) {
            Key *k = k_it++;
            if (!k)
                break;
            vector<Key *> l;
            rewrite_key(table, k, a, l);
            for (auto it = l.begin(); it != l.end(); ++it) {
                newList0.push_back(*it);
            }
        }
        lex->alter_info.key_list = newList0;
    }
}

static void
rewrite_insert_lex(LEX *lex, Analysis &a)
{
    // fields
    vector<FieldMeta *> fmVec;
    if (lex->field_list.head()) {
        auto it = List_iterator<Item>(lex->field_list);
        List<Item> newList;
        for (;;) {
            Item *i = it++;
            if (!i)
                break;
            assert(i->type() == Item::FIELD_ITEM);
            Item_field *ifd = static_cast<Item_field*>(i);
            fmVec.push_back(a.schema->getFieldMeta(ifd->table_name, ifd->field_name));
            vector<Item *> l;
            itemTypes.do_rewrite_insert(i, a, l, NULL);
            for (auto it0 = l.begin(); it0 != l.end(); ++it0) {
                newList.push_back(*it0);
            }
        }
        lex->field_list = newList;
    }

    if (fmVec.empty()) {
        // use the table order now
        const string &table =
            lex->select_lex.table_list.first->table_name;
        auto it = a.schema->tableMetaMap.find(table);
        assert(it != a.schema->tableMetaMap.end());
        TableMeta *tm = it->second;
        for (auto it0 = tm->fieldMetaMap.begin();
             it0 != tm->fieldMetaMap.end(); ++it0) {
            fmVec.push_back(it0->second);
        }
    }

    // values
    if (lex->many_values.head()) {
        auto it = List_iterator<List_item>(lex->many_values);
        List<List_item> newList;
        for (;;) {
            List_item *li = it++;
            if (!li)
                break;
            assert(li->elements == fmVec.size());
            List<Item> *newList0 = new List<Item>();
            auto it0 = List_iterator<Item>(*li);
            auto fmVecIt = fmVec.begin();
            for (;;) {
                Item *i = it0++;
                if (!i)
                    break;
                vector<Item *> l;
                itemTypes.do_rewrite_insert(i, a, l, *fmVecIt);
                for (auto it1 = l.begin(); it1 != l.end(); ++it1) {
                    newList0->push_back(*it1);
                }
                ++fmVecIt;
            }
            newList.push_back(newList0);
        }
        lex->many_values = newList;
    }
}

static void
do_query_analyze(const std::string &db, const std::string &q, LEX * lex, Analysis & analysis) {
    // iterate over the entire select statement..
    // based on st_select_lex::print in mysql-server/sql/sql_select.cc

    if (lex->sql_command == SQLCOM_CREATE_TABLE) {
        process_create_lex(lex, analysis);
        return;
    }

    process_table_list(&lex->select_lex.top_join_list, analysis);

    process_select_lex(&lex->select_lex,
            constraints(
                    lex->sql_command == SQLCOM_SELECT ? FULL_EncSet
                    : EMPTY_EncSet,
                              "select", 0, 0, true), analysis);

    if (lex->sql_command == SQLCOM_UPDATE) {
        auto item_it = List_iterator<Item>(lex->value_list);
        for (;;) {
            Item *item = item_it++;
            if (!item)
                break;

            analyze(item, constraints(FULL_EncSet, "update", item, 0, false), analysis);
        }
    }
}

/*
 * Analyzes how to encrypt and rewrite items in a query.
 * Results are set in analysis.
 */
static void
query_analyze(const std::string &db, const std::string &q, LEX * lex, Analysis & analysis)
{
    // optimize the query first
    optimize_table_list(&lex->select_lex.top_join_list, analysis);
    optimize_select_lex(&lex->select_lex, analysis);

    do_query_analyze(db, q, lex, analysis);
    //print(analysis.schema->tableMetaMap);

}


/*
 * Examines the embedded database and the encryption levels needed for a query (as given by analysis).
 *
 * Issues queries for decryption to the DBMS.
 *
 * Adjusts the metadata at the proxy about onion layers.
 *
 * Adjusts analysis to indicate the final encryption schemes to use.
 *
 * Returns negative on error.
 *
 */
static int
adjustOnions(const std::string &db, const Analysis & analysis)
{
    return 0;
}


FieldMeta::FieldMeta():encdesc(FULL_EncDesc)
{
    fname = "";
    sql_field = NULL;
    salt_name = "";
    has_salt = true;

}

TableMeta::TableMeta() {
    anonTableName = "";
    tableNo = 0;
}

TableMeta::~TableMeta()
{
    for (auto i = fieldMetaMap.begin(); i != fieldMetaMap.end(); i++)
        delete i->second;

}


/*
 * Rewrites lex by translating and encrypting based on information in analysis.
 *
 * Fills rmeta with information about how to decrypt fields returned.
 */
static int
lex_rewrite(const string & db, LEX * lex, Analysis & analysis)
{
    switch (lex->sql_command) {
    case SQLCOM_CREATE_TABLE:
        rewrite_create_lex(lex, analysis);
        break;
    case SQLCOM_INSERT:
    case SQLCOM_REPLACE:
        rewrite_insert_lex(lex, analysis);
        break;
    case SQLCOM_DROP_TABLE:
        rewrite_table_list(&lex->select_lex.table_list, analysis);
        break;
    default:
        rewrite_table_list(&lex->select_lex.top_join_list, analysis);
        rewrite_select_lex(&lex->select_lex, analysis);
        break;
    }
    return true;
}

static inline void
drop_table_update_meta(const string &q,
                       LEX *lex,
                       Analysis &a)
{
    MYSQL *m = a.conn();

    mysql_query_wrapper(m, "START TRANSACTION");

    TABLE_LIST *tbl = lex->select_lex.table_list.first;
    for (; tbl; tbl = tbl->next_local) {
        const string &table = tbl->table_name;

        ostringstream s;
        s << "DELETE proxy_db.table_info, proxy_db.column_info "
          << "FROM proxy_db.table_info INNER JOIN proxy_db.column_info "
          << "WHERE proxy_db.table_info.id = proxy_db.column_info.table_id "
          << "AND   proxy_db.table_info.name = " << sq(m, table);
        mysql_query_wrapper(m, s.str());

        a.schema->totalTables--;
        a.schema->tableMetaMap.erase(table);

        mysql_query_wrapper(m, q);
    }

    mysql_query_wrapper(m, "COMMIT");
}

static void
add_table_update_meta(const string &q,
                      LEX *lex,
                      Analysis &a)
{
    MYSQL *m = a.conn();

    mysql_query_wrapper(m, "START TRANSACTION");

    const string &table =
        lex->select_lex.table_list.first->table_name;
    TableMeta *tm = a.schema->tableMetaMap[table];
    assert(tm != NULL);

    {
        ostringstream s;
        s << "INSERT INTO proxy_db.table_info VALUES ("
          << tm->tableNo << ", "
          << sq(m, table) << ", "
          << sq(m, tm->anonTableName)
          << ")";

        mysql_query_wrapper(m, s.str());
    }

    for (auto it = tm->fieldMetaMap.begin();
         it != tm->fieldMetaMap.end();
         ++it) {

        FieldMeta *fm = it->second;
        assert(it->first == fm->fname);

        ostringstream s;
        s << "INSERT INTO proxy_db.column_info VALUES ("
          << "0, " /* auto assign id */
          << tm->tableNo << ", "
          << sq(m, fm->fname) << ", ";

#define __temp_write(o) \
        { \
            auto it = fm->onionnames.find(o); \
            if (it != fm->onionnames.end()) { s << sq(m, it->second) << ", "; } \
            else                            { s << "NULL, ";               } \
        }
        __temp_write(oDET);
        __temp_write(oOPE);
        __temp_write(oAGG);
        __temp_write(oSWP);
#undef __temp_write

        s << sq(m, fm->salt_name) << ", "
          << "1, " /* is_encrypted */
          << "1, " /* can_be_null  */
          << (fm->hasOnion(oOPE) ? "1" : "0") << ", "
          << (fm->hasOnion(oAGG) ? "1" : "0") << ", "
          << (fm->hasOnion(oSWP) ? "1" : "0") << ", "
          << (fm->has_salt       ? "1" : "0") << ", "
          << (fm->hasOnion(oOPE) ? "1" : "0") << ", " /* ope_used? */
          << (fm->hasOnion(oAGG) ? "1" : "0") << ", " /* agg_used? */
          << (fm->hasOnion(oSWP) ? "1" : "0") << ", " /* search_used? */
          << sq(m, fm->hasOnion(oOPE) ? levelnames[(int)fm->getOnionLevel(oOPE)] : "INVALID") << ", "
          << sq(m, levelnames[(int)fm->getOnionLevel(oDET)])
          << ")";

        mysql_query_wrapper(m, s.str());
    }

    //need to update embedded schema with the new table
    mysql_query_wrapper(m, q);

    mysql_query_wrapper(m, "COMMIT");
}

static int
updateMeta(const string & db, const string & q, LEX * lex, Analysis & a)
{
    switch (lex->sql_command) {
    // TODO: alter tables will need to modify the embedded DB schema
    case SQLCOM_DROP_TABLE:
        drop_table_update_meta(q, lex, a);
        break;
    case SQLCOM_CREATE_TABLE:
        add_table_update_meta(q, lex, a);
        break;
    default:
        // no-op
        break;
    }

    return adjustOnions(db, a);
}

Rewriter::Rewriter(const std::string & db) : db(db)
{
    // create mysql connection to embedded
    // server
    m = mysql_init(0);
    assert(m);
    mysql_options(m, MYSQL_OPT_USE_EMBEDDED_CONNECTION, 0);
    if (!mysql_real_connect(m, 0, 0, 0, 0, 0, 0, CLIENT_MULTI_STATEMENTS)) {
        mysql_close(m);
        cryptdb_err() << "mysql_real_connect: " << mysql_error(m);
    }
    // HACK: create this DB if it doesn't exist, for now
    string create_q = "CREATE DATABASE IF NOT EXISTS " + db;
    string use_q    = "USE " + db + ";";
    mysql_query_wrapper(m, create_q);
    mysql_query_wrapper(m, use_q);

    schema = new SchemaInfo();
    totalTables = 0;
    initSchema();
}

Rewriter::~Rewriter()
{
    mysql_close(m);
}

void
Rewriter::createMetaTablesIfNotExists()
{
    MYSQL *m = conn();
    mysql_query_wrapper(m, "CREATE DATABASE IF NOT EXISTS proxy_db");

    mysql_query_wrapper(m,
                   "CREATE TABLE IF NOT EXISTS proxy_db.table_info"
                   "( id bigint NOT NULL PRIMARY KEY"
                   ", name varchar(64) NOT NULL"
                   ", anon_name varchar(64) NOT NULL"
                   ", UNIQUE INDEX idx_table_name( name )"
                   ") ENGINE=InnoDB;");

    mysql_query_wrapper(m,
                   "CREATE TABLE IF NOT EXISTS proxy_db.column_info"
                   "( id bigint NOT NULL auto_increment PRIMARY KEY"
                   ", table_id bigint NOT NULL"
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
                   ") ENGINE=InnoDB;");
}

void
Rewriter::initSchema()
{
    createMetaTablesIfNotExists();

    MYSQL *m = conn();
    vector<string> tablelist;

    {
        mysql_query_wrapper(m, "SELECT id, name, anon_name FROM proxy_db.table_info");
        ScopedMySQLRes r(mysql_store_result(m));
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(r.res()))) {
            unsigned long *l = mysql_fetch_lengths(r.res());
            assert(l != NULL);
            TableMeta *tm = new TableMeta;
            tm->tableNo = (unsigned int) atoi(string(row[0], l[0]).c_str());
            tm->anonTableName = string(row[2], l[2]);
            tm->has_salt = false;
            schema->tableMetaMap[string(row[1], l[1])] = tm;
            schema->totalTables++;
        }
    }

    for (auto it = schema->tableMetaMap.begin();
         it != schema->tableMetaMap.end();
         ++it) {

        const string &origTableName = it->first;
        TableMeta *tm = it->second;

        string create_table_query;
        {
            string q = "SHOW CREATE TABLE " + origTableName;
            mysql_query_wrapper(m, q);
            ScopedMySQLRes r(mysql_store_result(m));
            assert(mysql_num_rows(r.res()) == 1);
            assert(mysql_num_fields(r.res()) == 2);
            MYSQL_ROW row = mysql_fetch_row(r.res());
            unsigned long *lengths = mysql_fetch_lengths(r.res());
            create_table_query = string(row[1], lengths[1]);
        }

        query_parse parser(db, create_table_query);
        LEX *lex = parser.lex();
        assert(lex->sql_command == SQLCOM_CREATE_TABLE);

        // fetch all the column info for this table
        {
            string q = "SELECT "
                       "c.name, "

                       "c.has_ope, "
                       "c.has_agg, "
                       "c.has_search, "

                       "c.anon_det_name, "
                       "c.anon_ope_name, "
                       "c.anon_agg_name, "
                       "c.anon_swp_name, "

                       "c.sec_level_det, "
                       "c.sec_level_ope, "

                       "c.salt_name, "
                       "c.is_encrypted, "
                       "c.can_be_null, "

                       "c.has_salt "

                       //TODO: what do these fields do?
                       //"c.ope_used, "
                       //"c.agg_used, "
                       //"c.search_used, "

                       "FROM proxy_db.column_info c, proxy_db.table_info t "
                       "WHERE t.name = '" + origTableName + "' AND c.table_id = t.id";
            mysql_query_wrapper(m, q);
            ScopedMySQLRes r(mysql_store_result(m));
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(r.res()))) {
                unsigned long *l = mysql_fetch_lengths(r.res());
                assert(l != NULL);

                FieldMeta *fm = new FieldMeta;
                fm->tm = tm;

                size_t i = 0, j = 0;
                fm->fname = string(row[i++], l[j++]);

                bool has_ope = string(row[i++], l[j++]) == "1";
                bool has_agg = string(row[i++], l[j++]) == "1";
                bool has_swp = string(row[i++], l[j++]) == "1";

                fm->onionnames[oDET] = string(row[i++], l[j++]);

                if (has_ope) { fm->onionnames[oOPE] = string(row[i++], l[j++]); }
                else         { i++; j++; }

                if (has_agg) { fm->onionnames[oAGG] = string(row[i++], l[j++]); }
                else         { i++; j++; }

                if (has_swp) { fm->onionnames[oSWP] = string(row[i++], l[j++]); }
                else         { i++; j++; }

                OnionLevelMap om;

                om[oDET] = string_to_sec_level(string(row[i++], l[j++]));

                if (has_ope) { om[oOPE] = string_to_sec_level(string(row[i++], l[j++])); }
                else         { i++; j++; }

                if (has_agg) { om[oAGG] = SECLEVEL::PLAIN_AGG; }

                if (has_swp) { om[oSWP] = SECLEVEL::PLAIN_SWP; }

                fm->encdesc = EncDesc(om);

                fm->salt_name = string(row[i++], l[j++]);

                i++; j++; // is_encrypted
                i++; j++; // can_be_null

                fm->has_salt = string(row[i++], l[j++]) == "1";

                tm->fieldNames.push_back(fm->fname);
                tm->fieldMetaMap[fm->fname] = fm;
            }
        }
    }
}

TableMeta *
SchemaInfo::getTableMeta(const string & table) {
    auto it = tableMetaMap.find(table);
    assert_s(it != tableMetaMap.end(), "could not find table " + table);
    return it->second;
}

FieldMeta *
SchemaInfo::getFieldMeta(const string & table, const string & field) {
    TableMeta * tm = getTableMeta(table);
    auto it = tm->fieldMetaMap.find(field);
    assert_s(it != tm->fieldMetaMap.end(), "could not find field " + field + " in table " +  table );
    return it->second;
}

void
Rewriter::setMasterKey(const string &mkey)
{
    cm = new CryptoManager(mkey);
}

string
Rewriter::rewrite(const string & q, Analysis & a)
{
    query_parse p(db, q);
    LEX *lex = p.lex();

    cerr << "query lex is " << *lex << "\n";

    Analysis analysis = Analysis(conn(), schema, cm);
    query_analyze(db, q, lex, analysis);

    int ret = updateMeta(db, q, lex, analysis);
    if (ret < 0) assert(false);

    lex_rewrite(db, lex, analysis);

    stringstream ss;

    ss << *lex;

    return ss.str();
}


ResType
Rewriter::decryptResults(ResType & dbres,
			 Analysis & a) {

    unsigned int rows = dbres.rows.size();

    unsigned int cols = dbres.names.size();

    ResType res = ResType();

    unsigned int index = 0;
      // un-anonymize the names
    for (auto it = dbres.names.begin(); it != dbres.names.end(); it++) {
	ReturnField rf = a.rmeta.rfmeta[index];
	if (rf.is_salt) {

	} else {
	    //need to return this field
	    res.names.push_back(rf.im->basefield->fname);

	}
	index++;
    }

    unsigned int real_cols = dbres.names.size();

    // switch types to original ones : TODO

    //allocate space in results for decrypted rows
    res.rows = vector<vector<SqlItem> >(rows);
    for (unsigned int i = 0; i < rows; i++) {
	res.rows[i] = vector<SqlItem>(real_cols);
    }

    // decrypt rows

    unsigned int col_index = 0;
    for (unsigned int c = 0; c < cols; c++) {
	ReturnField rf = a.rmeta.rfmeta[c];
	ItemMeta * im = rf.im;
	if (rf.is_salt) {

	} else {
	    for (unsigned int r = 0; r < rows; r++) {
		bool isBin;
		res.rows[r][col_index] = dbres.rows[r][c];
		res.rows[r][col_index].data = a.cm->crypt(cm->getmkey(), dbres.rows[r][c].data,
					     getTypeForDec(rf.im), getAnonName(rf.im), im->uptolevel, getMin(im->o), isBin);
	    }
	    col_index++;
	}

    }



    return dbres;
}



