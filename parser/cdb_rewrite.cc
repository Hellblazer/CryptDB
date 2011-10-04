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

#include <parser/Translator.hh>

#include <sql_select.h>
#include <sql_delete.h>
#include <sql_insert.h>
#include <sql_update.h>

#include <parser/embedmysql.hh>
#include <parser/stringify.hh>

#include <util/errstream.hh>
#include <util/cleanup.hh>
#include <util/rob.hh>


#include <parser/cdb_rewrite.hh>


static unsigned int counter = 0;



#define UNIMPLEMENTED \
    throw runtime_error(string("Unimplemented: ") + \
                        string(__PRETTY_FUNCTION__))

using namespace std;

static inline bool
FieldQualifies(const string &restriction,
               const string &field)
{
    return restriction.empty() || restriction == field;
}


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
            if (it->second.second.empty()) {
                m[it->first] = LevelFieldPair(
                        sl, it2->second.second);
            } else if (it2->second.second.empty()) {
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
    static const onion onion_order[] = {
        oAGG,
        oSWP,
        oDET,
        oOPE,
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
            << ", field `" << (it.second.second.empty() ? "*" : it.second.second) << "`"
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
        << ", field `" << (p.second.second.empty() ? "*" : p.second.second) << "`"
        << ")";
    return out;
}

static inline char *
scramble_table_name(const char *orig_table_name,
                    size_t      orig_table_name_length,
                    size_t     &new_table_length)
{
    THD *thd = current_thd;
    assert(thd);
    string tname(orig_table_name, orig_table_name_length);
    // TODO(stephentu):
    // A) do an actual mapping
    // B) figure out where to actually allocate the memory for strs
    //    (right now, just putting it in the THD mem pools)
    string tname0 = anonymizeTableName(counter++, tname, false);
    char *tname0p = thd->strmake(tname0.c_str(), tname0.size());
    new_table_length = tname0.size();
    return tname0p;
}

class CItemType {
 public:
    virtual EncSet do_gather(Item *, const constraints&, Analysis &) const = 0;
    virtual void   do_enforce(Item *, const constraints&, Analysis &) const = 0;
    virtual Item * do_optimize(Item *, Analysis &) const = 0;
    virtual Item * do_rewrite(Item *, Analysis &) const = 0;
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
        *i = i0;
    }
}

extern "C" void *create_embedded_thd(int client_flag);

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
        if (mysql_query(m, q.c_str()))
            fatal() << "mysql_query: " << mysql_error(m);

        // HACK(stephentu):
        // Calling mysql_query seems to have destructive effects
        // on the current_thd. Thus, we must call create_embedded_thd
        // again.
        assert(create_embedded_thd(0));
        assert(current_thd != NULL);

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

                switch (field->type) {
                    case MYSQL_TYPE_SHORT:
                    case MYSQL_TYPE_LONG:
                    case MYSQL_TYPE_LONGLONG:
                    case MYSQL_TYPE_INT24:
                        {
                            long long int v = strtoll(p, NULL, 10);
                            rep = new Item_int(v);
                        }
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

template <class T>
static Item *
do_rewrite_type_args(T *i, Analysis &a) {
    Item **args = i->arguments();
    for (uint x = 0; x < i->argument_count(); x++) {
        rewrite(&args[x], a);
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
 private:
    virtual EncSet do_gather_type(T *, const constraints&, Analysis & a) const = 0;
    virtual void   do_enforce_type(T *, const constraints&, Analysis & a) const = 0;
    virtual Item * do_optimize_type(T *i, Analysis & a) const {
        return do_optimize_const_item(i, a);
    }
    virtual Item * do_rewrite_type(T *i, Analysis & a) const { return i; }
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

        string fieldname = extract_fieldname(i);

        // check compatibility for each of the constraints given
        // in the incoming enc set, either filtering them out, or
        // by modification
        OnionLevelFieldMap m;
        for (auto it = tr.encset.osl.begin();
             it != tr.encset.osl.end();
             ++it) {
            // if the field is a wildcard, then replace it with this field
            // (or if it's the same field
            if (FieldQualifies(it->second.second, fieldname)) {
                m[it->first] = it->second;
                m[it->first].second = fieldname;
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
                            it->second.second < fieldname ?
                                it->second.second : fieldname);
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
        auto it = a.fieldToMeta.find(fieldname);
        if (it == a.fieldToMeta.end()) {
            //todo: there should be a map of FULL_EncSets depending on object type
            a.fieldToMeta[fieldname] = new FieldMeta(FULL_EncDesc);
            it = a.fieldToMeta.find(fieldname);
        }
        if (it->second->exposedLevels.restrict(encpair.first,
                                               encpair.second.first)) {
            cerr << "has not converged\n";
            a.hasConverged = false;
        }
        cerr << "ENCSET FOR FIELD " << fieldname << " is " << a.fieldToMeta[fieldname]->exposedLevels << "\n";
    }

    virtual Item *
    do_rewrite_type(Item_field *i, Analysis & a) const
    {
        // fix table name
        size_t l = 0;
        i->table_name = scramble_table_name(i->table_name,
                                            strlen(i->table_name),
                                            l);
        // TODO: pick the column corresponding to the onion we want

        return i;
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
        im->basekey   = c.second.second;
    }
    virtual Item * do_optimize_type(Item_string *i, Analysis & a) const {
        return i;
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
        im->basekey   = c.second.second;
    }
    virtual Item * do_optimize_type(Item_num *i, Analysis & a) const {
        return i;
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
        im->basekey   = c.second.second;
    }
    virtual Item * do_optimize_type(Item_decimal *i, Analysis & a) const {
        return i;
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
        // TODO: replace with a hom-add function...
        return do_rewrite_type_args(i, a);
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

    if (select_lex->join && select_lex->join->conds)
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
        cerr << "before analyze item " << *item << "\n";
        analyze(item, tr, a);
    }

    if (select_lex->where)
        analyze(select_lex->where, constraints(FULL_EncSet, "where", select_lex->where, 0), a);

    if (select_lex->join && select_lex->join->conds)
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
    for (;;) {
        if (!item_it++)
            break;
        rewrite(item_it.ref(), a);
    }

    if (select_lex->where)
        rewrite(&select_lex->where, a);

    if (select_lex->join && select_lex->join->conds)
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
            Analysis a;
            process_select_lex(u->first_select(), constraints(EMPTY_EncSet,  "sub-select", 0, 0, false), a);
        }
    }
}

static void
rewrite_table_list(List<TABLE_LIST> *tll, Analysis & a)
{

    List_iterator<TABLE_LIST> join_it(*tll);
    for (;;) {
        TABLE_LIST *t = join_it++;
        if (!t)
            break;


        t->table_name = scramble_table_name(t->table_name,
                                            t->table_name_length,
                                            t->table_name_length);

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
do_query_analyze(const std::string &db, const std::string &q, LEX * lex, Analysis & analysis) {
    // iterate over the entire select statement..
    // based on st_select_lex::print in mysql-server/sql/sql_select.cc
    cerr << "in do_query_analyze\n";
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

    //runs at most twice
    while (!analysis.hasConverged) {
        analysis.hasConverged = true;
        do_query_analyze(db, q, lex, analysis);
    }
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
static
int adjustOnions(const std::string &db, const Analysis & analysis)
{
    return 0;
}

/*
 * Rewrites lex by translating and encrypting based on information in analysis.
 *
 * Fills rmeta with information about how to decrypt fields returned.
 */
static int
lex_rewrite(const string & db, LEX * lex, Analysis & analysis, ReturnMeta & rmeta)
{
    rewrite_table_list(&lex->select_lex.top_join_list, analysis);
    rewrite_select_lex(&lex->select_lex, analysis);
    return true;
}

string
rewrite(const string & db, const string & q, ReturnMeta & rmeta)
{
    query_parse p(db, q);
    LEX *lex = p.lex();

    cerr << "query lex is " << *lex << "\n";

    Analysis analysis;
    query_analyze(db, q, lex, analysis);

    assert(adjustOnions(db, analysis) >= 0);

    lex_rewrite(db, lex, analysis, rmeta);

    stringstream ss;
    ss << *lex;

    return ss.str();
}

/*
ResType
decryptResults(ResType & dbres, const ReturnMeta & rmeta) {
    //todo
    return dbres;
}
*/
