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


using namespace std;

#define CIPHER_TYPES(m)                                                     \
        m(none)     /* no data needed (blind writes) */                     \
        m(any)      /* just need to decrypt the result */                   \
        m(plain)    /* evaluate Item on the server, e.g. for WHERE */       \
        m(order)    /* evaluate order on the server, e.g. for SORT BY */    \
        m(equal)    /* evaluate dups on the server, e.g. for GROUP BY */    \
        m(like)     /* need to do LIKE */                                   \
        m(homadd)   /* addition */

enum class cipher_type {
#define __temp_m(n) n,
    CIPHER_TYPES(__temp_m)
#undef __temp_m
};

static const string cipher_type_names[] = {
#define __temp_m(n) #n,
    CIPHER_TYPES(__temp_m)
#undef __temp_m
};

EncSet::EncSet(map<onion, SECLEVEL> input)
{
    osl = input;
}

EncSet::EncSet()
{
    osl = FULL_EncSet.osl;
}

int
EncSet::restrict(onion o, SECLEVEL maxl)
{
    //TODO:
    //assert(maxl is on onion o);

    auto it = osl.find(o);
    if (it == osl.end()) {
        return -1;
    }
    if (it->second > maxl) {
        osl[o] = maxl;
        return 0;
    }

    return -1;
}

int
EncSet::remove(onion o)
{
    auto it = osl.find(o);

    if (it == osl.end()) {
        return -1;
    }

    osl.erase(it);
    return 0;
}

EncSet
EncSet::intersect(const EncSet & es2) const
{
    map<onion, SECLEVEL> res = map<onion, SECLEVEL>();
    for (map<onion, SECLEVEL>::const_iterator it2 = es2.osl.begin() ; it2 != es2.osl.end(); it2++) {
        map<onion, SECLEVEL>::const_iterator it = osl.find(it2->first);
        if (it != osl.end()) {
        res[it2->first] = (SECLEVEL)min((int)it->second, (int)it2->second);
        }
    }
    return EncSet(res);
}

pair<onion, SECLEVEL>
EncSet::chooseOne() const
{
    if (osl.size() == 0) {
        return pair<onion, SECLEVEL>(oINVALID, SECLEVEL::INVALID);
    }
    auto it = osl.find(oAGG);
    if (it != osl.end()) {
        return pair<onion, SECLEVEL>(oAGG, it->second);
    }
    it = osl.find(oSWP);
    if (it != osl.end()){
        return pair<onion, SECLEVEL>(oSWP, it->second);
    }
    it = osl.find(oDET);
    if (it != osl.end()){
        return pair<onion, SECLEVEL>(oDET, it->second);
    }
    it = osl.find(oOPE);
    if (it != osl.end()){
        return pair<onion, SECLEVEL>(oOPE, it->second);
    }

    return pair<onion, SECLEVEL>(oINVALID, SECLEVEL::INVALID);
}

EncSet::EncSet(const EncSet & es)
{
    osl = es.osl;
}

static ostream&
operator<<(ostream &out, const EncSet & es)
{
    if (es.osl.size() == 0) {
        out << "empty encset";
    }
    for (auto it : es.osl) {
        out << "(onion " << it.first;
        out << ", " << " level " << levelnames[(int)it.second] << ") ";
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


class CItemType {
 public:
    virtual void do_analyze(Item *, const constraints&, Analysis & a) const = 0;

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
        //cerr << "ADDING to types (" << t << " " << ct << ")\n";
    }

    void do_analyze(Item *i, const constraints &tr, Analysis & a) const {
        //cerr << "CItemTypeDir do_analyze " << *i << " encset is " << tr.encset << "\n";
        //cerr << "this item is of type " << i->type() << "\n";
        lookup(i)->do_analyze(i, tr, a);
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
static void
analyze(Item *i, const constraints &tr, Analysis & a)
{
    //cerr << "before itemTypes.do_analyze item" << *i << "\n";
    itemTypes.do_analyze(i, tr, a);
    
}


/*
 * CItemType classes for supported Items: supporting machinery.
 */
template<class T>
class CItemSubtype : public CItemType {
    virtual void do_analyze(Item *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtype do_analyze " << *i << " encset " << tr.encset << "\n";
        do_analyze_type((T*) i, tr, a);
    }

 private:
    virtual void do_analyze_type(T *, const constraints&, Analysis & a) const = 0;
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

static class ANON : public CItemSubtypeIT<Item_field, Item::Type::FIELD_ITEM> {
    virtual void do_analyze_type(Item_field *i, const constraints &tr, Analysis & a) const {
    cerr << "CItemSubtypeIT do_analyze " << *i << "\n";
    
    //apply encsets from constraints

    //there are more than one onion that can support this operation so we need to pick one
    pair<onion, SECLEVEL> encpair = tr.encset.chooseOne();
    
    stringstream fieldtemp;
    fieldtemp << *i;
    string fieldname = fieldtemp.str();
    auto it = a.fieldToMeta.find(fieldname);
    if (it == a.fieldToMeta.end()) {
        //todo: there should be a map of FULL_EncSets depending on object type
        a.fieldToMeta[fieldname] = new FieldMeta(FULL_EncSet);
        it = a.fieldToMeta.find(fieldname);
    }
    int res = it->second->exposedLevels.restrict(encpair.first, encpair.second);
    
    if (res>=0) {
        cerr << "has not converged\n";
        a.hasConverged = false;
    }
    
    cerr << "ENCSET FOR FIELD " << fieldname << " is " << a.fieldToMeta[fieldname]->exposedLevels << "\n";
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_string, Item::Type::STRING_ITEM> {
    virtual void do_analyze_type(Item_string *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT const string do_analyze " << *i << "\n";
        /* constant strings are always ok */
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_num, Item::Type::INT_ITEM> {
    virtual void do_analyze_type(Item_num *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT num do_analyze " << *i << "\n";
        /* constant ints are always ok */
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_decimal, Item::Type::DECIMAL_ITEM> {
    virtual void do_analyze_type(Item_decimal *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeIT decimal do_analyze " << *i << "\n";
        /* constant decimals are always ok */
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_neg, Item_func::Functype::NEG_FUNC> {
    virtual void do_analyze_type(Item_func_neg *i, const constraints &tr, Analysis & a) const {
        analyze(i->arguments()[0], tr, a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_not, Item_func::Functype::NOT_FUNC> {
    virtual void do_analyze_type(Item_func_not *i, const constraints &tr, Analysis & a) const {
        analyze(i->arguments()[0], tr, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_subselect, Item::Type::SUBSELECT_ITEM> {
    virtual void do_analyze_type(Item_subselect *i, const constraints &tr, Analysis & a) const {
    
        st_select_lex *select_lex = i->get_select_lex();
        process_select_lex(select_lex, tr, a);
    }
} ANON;

extern const char str_in_optimizer[] = "<in_optimizer>";
static class ANON : public CItemSubtypeFN<Item_in_optimizer, str_in_optimizer> {
    virtual void do_analyze_type(Item_in_optimizer *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemSubtypeFN do_analyze " << *i << "\n";
        
        Item **args = i->arguments();
        analyze(args[0], constraints(EMPTY_EncSet, "in_opt", i, &tr), a);
        analyze(args[1], constraints(EMPTY_EncSet,  "in_opt", i, &tr), a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_cache, Item::Type::CACHE_ITEM> {
    virtual void do_analyze_type(Item_cache *i, const constraints &tr, Analysis & a) const {
        
        Item *example = (*i).*rob<Item_cache, Item*, &Item_cache::example>::ptr();
        if (example)
            analyze(example, tr, a);
    }
} ANON;

template<Item_func::Functype FT, class IT>
class CItemCompare : public CItemSubtypeFT<Item_func, FT> {
    virtual void do_analyze_type(Item_func *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemCompare do_analyze func " << *i << "\n";
                
        EncSet t2;
        
        if (FT == Item_func::Functype::EQ_FUNC ||
                FT == Item_func::Functype::EQUAL_FUNC ||
                FT == Item_func::Functype::NE_FUNC)
        {
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

        analyze(args[0], constraints(new_encset, reason, i, &tr), a);
        analyze(args[1], constraints(new_encset, reason, i, &tr), a);
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
    virtual void do_analyze_type(Item_cond *i, const constraints &tr, Analysis & a) const {
        cerr << "CItemCond do_analyze " << *i << "\n";
        //cerr << "do_a_t item_cond reason " << tr << "\n";
        auto it = List_iterator<Item>(*i->argument_list());
        //we split the current item in the different subexpressions
        for (;;) {
            Item *argitem = it++;
            if (!argitem)
                break;
            analyze(argitem, constraints(tr.encset, "cond", i, &tr), a);
        }
    }
};

static CItemCond<Item_func::Functype::COND_AND_FUNC, Item_cond_and> ANON;
static CItemCond<Item_func::Functype::COND_OR_FUNC,  Item_cond_or>  ANON;

template<Item_func::Functype FT>
class CItemNullcheck : public CItemSubtypeFT<Item_bool_func, FT> {
    virtual void do_analyze_type(Item_bool_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet,  "nullcheck", i, &tr), a);
    }
};

static CItemNullcheck<Item_func::Functype::ISNULL_FUNC> ANON;
static CItemNullcheck<Item_func::Functype::ISNOTNULL_FUNC> ANON;

static class ANON : public CItemSubtypeFT<Item_func_get_system_var, Item_func::Functype::GSYSVAR_FUNC> {
    virtual void do_analyze_type(Item_func_get_system_var *i, const constraints &tr, Analysis & a) const {}
} ANON;

template<const char *NAME>
class CItemAdditive : public CItemSubtypeFN<Item_func_additive_op, NAME> {
    virtual void do_analyze_type(Item_func_additive_op *i, const constraints &tr, Analysis & a) const {
            
        //TODO
        /*
          Item **args = i->arguments();
          if (tr.t == cipher_type::any) {
            analyze(args[0], constraints(cipher_type::homadd, "additive", i, &tr), a);
            analyze(args[1], constraints(cipher_type::homadd, "additive", i, &tr), a);
        } else {
            analyze(args[0], constraints(EMPTY_EncSet, "additivex", i, &tr), a);
            analyze(args[1], constraints(EMPTY_EncSet, "additivex", i, &tr), a);
            }*/
    }
};

extern const char str_plus[] = "+";
static CItemAdditive<str_plus> ANON;

extern const char str_minus[] = "-";
static CItemAdditive<str_minus> ANON;

template<const char *NAME>
class CItemMath : public CItemSubtypeFN<Item_func, NAME> {
    virtual void do_analyze_type(Item_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
        analyze(args[x], constraints(EMPTY_EncSet, "math", i, &tr), a);
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
    virtual void do_analyze_type(Item_func_if *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        analyze(args[0], constraints(FULL_EncSet, "if_cond", i, &tr), a);
        analyze(args[1], tr, a);
        analyze(args[2], tr, a);
    }
} ANON;

extern const char str_nullif[] = "nullif";
static class ANON : public CItemSubtypeFN<Item_func_nullif, str_nullif> {
    virtual void do_analyze_type(Item_func_nullif *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EQ_EncSet, "nullif", i, &tr), a);
    }
} ANON;

extern const char str_coalesce[] = "coalesce";
static class ANON : public CItemSubtypeFN<Item_func_coalesce, str_coalesce> {
    virtual void do_analyze_type(Item_func_coalesce *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], tr, a);
    }
} ANON;

extern const char str_case[] = "case";
static class ANON : public CItemSubtypeFN<Item_func_case, str_case> {
    virtual void do_analyze_type(Item_func_case *i, const constraints &tr, Analysis & a) const {
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
    }
} ANON;

template<const char *NAME>
class CItemStrconv : public CItemSubtypeFN<Item_str_conv, NAME> {
    virtual void do_analyze_type(Item_str_conv *i, const constraints & tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet, "strconv", i, &tr), a);
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
    virtual void do_analyze_type(Item_func *i, const constraints &tr, Analysis & a) const {}
};

extern const char str_found_rows[] = "found_rows";
static CItemLeafFunc<str_found_rows> ANON;

extern const char str_last_insert_id[] = "last_insert_id";
static CItemLeafFunc<str_last_insert_id> ANON;

extern const char str_rand[] = "rand";
static CItemLeafFunc<str_rand> ANON;

static class ANON : public CItemSubtypeFT<Item_extract, Item_func::Functype::EXTRACT_FUNC> {
    virtual void do_analyze_type(Item_extract *i, const constraints &tr, Analysis & a) const {
        /* XXX perhaps too conservative */
        analyze(i->arguments()[0], constraints(EMPTY_EncSet, "extract", i, &tr), a);
    }
} ANON;

template<const char *NAME>
class CItemDateExtractFunc : public CItemSubtypeFN<Item_int_func, NAME> {
    virtual void do_analyze_type(Item_int_func *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            /* assuming we separately store different date components */
            analyze(args[x], tr, a);
        }
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
    virtual void do_analyze_type(Item_date_add_interval *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            /* XXX perhaps too conservative */
            analyze(args[x], constraints(EMPTY_EncSet, "date_add", i, &tr), a);
        }
    }
} ANON;

template<const char *NAME>
class CItemDateNow : public CItemSubtypeFN<Item_func_now, NAME> {
    virtual void do_analyze_type(Item_func_now *i, const constraints &tr, Analysis & a) const {}
};

extern const char str_now[] = "now";
static CItemDateNow<str_now> ANON;

extern const char str_utc_timestamp[] = "utc_timestamp";
static CItemDateNow<str_utc_timestamp> ANON;

extern const char str_sysdate[] = "sysdate";
static CItemDateNow<str_sysdate> ANON;

template<const char *NAME>
class CItemBitfunc : public CItemSubtypeFN<Item_func_bit, NAME> {
    virtual void do_analyze_type(Item_func_bit *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EMPTY_EncSet, "bitfunc", i, &tr), a);
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
    virtual void do_analyze_type(Item_func_like *i, const constraints &tr, Analysis & a) const {
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
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func, Item_func::Functype::FUNC_SP> {
    void error(Item_func *i) const __attribute__((noreturn)) {
        thrower() << "unsupported store procedure call " << *i;
    }

    virtual void do_analyze_type(Item_func *i, const constraints &tr, Analysis & a) const __attribute__((noreturn)) { error(i); }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_in, Item_func::Functype::IN_FUNC> {
    virtual void do_analyze_type(Item_func_in *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
        analyze(args[x], constraints(EQ_EncSet, "in", i, &tr), a);
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_func_in, Item_func::Functype::BETWEEN> {
    virtual void do_analyze_type(Item_func_in *i, const constraints &tr, Analysis & a) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
        analyze(args[x], constraints(ORD_EncSet, "between", i, &tr), a);
    }
} ANON;

template<const char *FN>
class CItemMinMax : public CItemSubtypeFN<Item_func_min_max, FN> {
    virtual void do_analyze_type(Item_func_min_max *i, const constraints &tr, Analysis & a) const {
        //cerr << "do_a_t Item_fuc_min_max reason " << tr << "\n";
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(ORD_EncSet, "min/max", i, &tr), a);
    }
};

extern const char str_greatest[] = "greatest";
static CItemMinMax<str_greatest> ANON;

extern const char str_least[] = "least";
static CItemMinMax<str_least> ANON;

extern const char str_strcmp[] = "strcmp";
static class ANON : public CItemSubtypeFN<Item_func_strcmp, str_strcmp> {
    virtual void do_analyze_type(Item_func_strcmp *i, const constraints &tr, Analysis & a) const {
        //cerr << "do_a_t Item_func_strcmp reason " << tr << "\n";
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], constraints(EQ_EncSet, "strcmp", i, &tr), a);
    }
} ANON;

template<Item_sum::Sumfunctype SFT>
class CItemCount : public CItemSubtypeST<Item_sum_count, SFT> {
    virtual void do_analyze_type(Item_sum_count *i, const constraints &tr, Analysis & a) const {
    //cerr << "do_a_t Item_sum_count reason " << tr << "\n";
    if (i->has_with_distinct())
        analyze(i->get_arg(0), constraints(EQ_EncSet, "sum", i, &tr, false), a);
    }
};

static CItemCount<Item_sum::Sumfunctype::COUNT_FUNC> ANON;
static CItemCount<Item_sum::Sumfunctype::COUNT_DISTINCT_FUNC> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemChooseOrder : public CItemSubtypeST<Item_sum_hybrid, SFT> {
    virtual void do_analyze_type(Item_sum_hybrid *i, const constraints &tr, Analysis & a) const {
    //cerr << "do_a_t Item_sum_hybrid reason " << tr << "\n";
    analyze(i->get_arg(0), constraints(ORD_EncSet, "min/max_agg", i, &tr, false), a);
    }
};

static CItemChooseOrder<Item_sum::Sumfunctype::MIN_FUNC> ANON;
static CItemChooseOrder<Item_sum::Sumfunctype::MAX_FUNC> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemSum : public CItemSubtypeST<Item_sum_sum, SFT> {
    virtual void do_analyze_type(Item_sum_sum *i, const constraints &tr, Analysis & a) const {
    cerr << "do_a_t Item_sum_sum reason " << tr  << "\n";
    if (i->has_with_distinct())
        analyze(i->get_arg(0), constraints(EQ_EncSet, "agg_distinct", i, &tr, false), a);

    analyze(i->get_arg(0), constraints(tr.encset.intersect(ADD_EncSet), "sum/avg", i, &tr, false), a);

    }
};

static CItemSum<Item_sum::Sumfunctype::SUM_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::SUM_DISTINCT_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::AVG_FUNC> ANON;
static CItemSum<Item_sum::Sumfunctype::AVG_DISTINCT_FUNC> ANON;

static class ANON : public CItemSubtypeST<Item_sum_bit, Item_sum::Sumfunctype::SUM_BIT_FUNC> {
    virtual void do_analyze_type(Item_sum_bit *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_sum_bit reason " << tr << "\n";
        analyze(i->get_arg(0), constraints(EMPTY_EncSet, "bitagg", i, &tr, false), a);
    }
} ANON;

static class ANON : public CItemSubtypeST<Item_func_group_concat, Item_sum::Sumfunctype::GROUP_CONCAT_FUNC> {
    virtual void do_analyze_type(Item_func_group_concat *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_func_group reason " << tr << "\n";
        uint arg_count_field = (*i).*rob<Item_func_group_concat, uint,
                &Item_func_group_concat::arg_count_field>::ptr();
        for (uint x = 0; x < arg_count_field; x++) {
            /* XXX could perform in the proxy.. */
            analyze(i->get_arg(x), constraints(EMPTY_EncSet, "group_concat", i, &tr), a);
        }

        /* XXX order, unused in trace queries.. */
    }
} ANON;

static class ANON : public CItemSubtypeFT<Item_char_typecast, Item_func::Functype::CHAR_TYPECAST_FUNC> {
    virtual void do_analyze_type(Item_char_typecast *i, const constraints &tr, Analysis & a) const {
        thrower() << "what does Item_char_typecast do?";
    }
} ANON;

extern const char str_cast_as_signed[] = "cast_as_signed";
static class ANON : public CItemSubtypeFN<Item_func_signed, str_cast_as_signed> {
    virtual void do_analyze_type(Item_func_signed *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_func_signed reason " << tr << "\n";
        analyze(i->arguments()[0], tr, a);
    }
} ANON;

static class ANON : public CItemSubtypeIT<Item_ref, Item::Type::REF_ITEM> {
    virtual void do_analyze_type(Item_ref *i, const constraints &tr, Analysis & a) const {
        cerr << "do_a_t Item_ref reason " << tr << "\n";
        if (i->ref) {
            analyze(*i->ref, tr, a);
        } else {
            thrower() << "how to resolve Item_ref::ref?";
        }
    }
} ANON;


/*
 * Some helper functions.
 */
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

    if (select_lex->having)
        analyze(select_lex->having, constraints(FULL_EncSet, "having", select_lex->having, 0), a);

    for (ORDER *o = select_lex->group_list.first; o; o = o->next)
        analyze(*o->item, constraints(EQ_EncSet, "group", *o->item, 0), a);

    for (ORDER *o = select_lex->order_list.first; o; o = o->next)
        analyze(*o->item, constraints(ORD_EncSet,
                          "order", *o->item, 0, select_lex->select_limit ? false : true), a);
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

        std::string db(t->db, t->db_length);
        std::string table_name(t->table_name, t->table_name_length);
        std::string alias(t->alias);

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
    cerr << "in query_analyze\n";
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
