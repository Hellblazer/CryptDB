#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <set>
#include <algorithm>

#include <stdio.h>

#include "errstream.h"
#include "stringify.h"
#include "cleanup.h"

#include "sql_select.h"

#define CONCAT2(a, b)   a ## b
#define CONCAT(a, b)    CONCAT2(a, b)
#define ANON            CONCAT(__anon_id_, __COUNTER__)

static bool debug = true;

#define CIPHER_TYPES(m)                                                     \
    m(any)    /* just need to decrypt the result */                         \
    m(plain)  /* need to evaluate Item on the server, e.g. for WHERE */     \
    m(order)  /* need to evaluate order on the server, e.g. for SORT BY */  \
    m(equal)  /* need to evaluate dups on the server, e.g. for GROUP BY */  \
    m(like)   /* need to do LIKE */                                         \
    m(homadd) /* addition */

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

static ostream&
operator<<(ostream &out, cipher_type &t)
{
    return out << cipher_type_names[(int) t];
}

class CItemType {
 public:
    virtual void do_analyze(Item *, cipher_type) const = 0;
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

    void do_analyze(Item *i, cipher_type t) const {
        lookup(i)->do_analyze(i, t);
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

static class CItemBaseDir : public CItemTypeDir<Item::Type> {
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
analyze(Item *i, cipher_type t)
{
    if (!i->const_item())
        itemTypes.do_analyze(i, t);
}


/*
 * CItemType classes for supported Items: supporting machinery.
 */
template<class T>
class CItemSubtype : public CItemType {
    virtual void do_analyze(Item *i, cipher_type t) const { do_analyze((T*) i, t); }
 private:
    virtual void do_analyze(T *, cipher_type) const = 0;
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
static void process_select_lex(st_select_lex *select_lex, cipher_type t);

static class CItemField : public CItemSubtypeIT<Item_field, Item::Type::FIELD_ITEM> {
    void do_analyze(Item_field *i, cipher_type t) const {
        cout << "FIELD " << *i << " CIPHER " << t << endl;
    }
} ANON;

static class CItemString : public CItemSubtypeIT<Item_string, Item::Type::STRING_ITEM> {
    void do_analyze(Item_string *i, cipher_type t) const {
        /* constant strings are always ok */
    }
} ANON;

static class CItemInt : public CItemSubtypeIT<Item_num, Item::Type::INT_ITEM> {
    void do_analyze(Item_num *i, cipher_type t) const {
        /* constant ints are always ok */
    }
} ANON;

static class CItemDecimal : public CItemSubtypeIT<Item_decimal, Item::Type::DECIMAL_ITEM> {
    void do_analyze(Item_decimal *i, cipher_type t) const {
        /* constant decimals are always ok */
    }
} ANON;

static class CItemNeg : public CItemSubtypeFT<Item_func_neg, Item_func::Functype::NEG_FUNC> {
    void do_analyze(Item_func_neg *i, cipher_type t) const {
        analyze(i->arguments()[0], t);
    }
} ANON;

static class CItemSubselect : public CItemSubtypeIT<Item_subselect, Item::Type::SUBSELECT_ITEM> {
    void do_analyze(Item_subselect *i, cipher_type t) const {
        st_select_lex *select_lex = i->get_select_lex();
        process_select_lex(select_lex, t);
    }
} ANON;

extern const char str_in_optimizer[] = "<in_optimizer>";
static class CItemSubselectInopt : public CItemSubtypeFN<Item_in_optimizer, str_in_optimizer> {
    void do_analyze(Item_in_optimizer *i, cipher_type t) const {
        Item **args = i->arguments();
        analyze(args[0], cipher_type::any);
        analyze(args[1], cipher_type::any);
    }
} ANON;

class Item_cache_extractor : public Item_cache {
 public:
    /* Why is Item_cache::example a protected field?  This is ugly.. */
    static Item *get_example(Item_cache *i) {
        Item_cache_extractor *ii = (Item_cache_extractor *) i;
        return ii->example;
    }
};

static class CItemCache : public CItemSubtypeIT<Item_cache, Item::Type::CACHE_ITEM> {
    void do_analyze(Item_cache *i, cipher_type t) const {
        Item *example = Item_cache_extractor::get_example(i);
        if (example)
            analyze(example, t);
    }
} ANON;

template<Item_func::Functype FT, class IT>
class CItemCompare : public CItemSubtypeFT<Item_func, FT> {
    void do_analyze(Item_func *i, cipher_type t) const {
        cipher_type t2;
        if (FT == Item_func::Functype::EQ_FUNC ||
            FT == Item_func::Functype::EQUAL_FUNC ||
            FT == Item_func::Functype::NE_FUNC)
        {
            t2 = cipher_type::equal;
        } else {
            t2 = cipher_type::order;
        }

        Item **args = i->arguments();
        analyze(args[0], t2);
        analyze(args[1], t2);
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
    void do_analyze(Item_cond *i, cipher_type t) const {
        auto it = List_iterator<Item>(*i->argument_list());
        for (;;) {
            Item *argitem = it++;
            if (!argitem)
                break;

            analyze(argitem, cipher_type::plain);
        }
    }
};

static CItemCond<Item_func::Functype::COND_AND_FUNC, Item_cond_and> ANON;
static CItemCond<Item_func::Functype::COND_OR_FUNC,  Item_cond_or>  ANON;

template<Item_func::Functype FT>
class CItemNullcheck : public CItemSubtypeFT<Item_bool_func, FT> {
    void do_analyze(Item_bool_func *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::any);
    }
};

static CItemNullcheck<Item_func::Functype::ISNULL_FUNC> ANON;
static CItemNullcheck<Item_func::Functype::ISNOTNULL_FUNC> ANON;

static class CItemSysvar : public CItemSubtypeFT<Item_func_get_system_var, Item_func::Functype::GSYSVAR_FUNC> {
    void do_analyze(Item_func_get_system_var *i, cipher_type t) const {}
} ANON;

template<const char *NAME>
class CItemAdditive : public CItemSubtypeFN<Item_func_additive_op, NAME> {
    void do_analyze(Item_func_additive_op *i, cipher_type t) const {
        Item **args = i->arguments();
        if (t == cipher_type::any) {
            analyze(args[0], cipher_type::homadd);
            analyze(args[1], cipher_type::homadd);
        } else {
            analyze(args[0], cipher_type::plain);
            analyze(args[1], cipher_type::plain);
        }
    }
};

extern const char str_plus[] = "+";
static CItemAdditive<str_plus> ANON;

extern const char str_minus[] = "-";
static CItemAdditive<str_minus> ANON;

template<const char *NAME>
class CItemMath : public CItemSubtypeFN<Item_func, NAME> {
    void do_analyze(Item_func *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::plain);
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

extern const char str_pow[] = "pow";
static CItemMath<str_pow> ANON;

extern const char str_radians[] = "radians";
static CItemMath<str_radians> ANON;

extern const char str_if[] = "if";
static class CItemIf : public CItemSubtypeFN<Item_func_if, str_if> {
    void do_analyze(Item_func_if *i, cipher_type t) const {
        Item **args = i->arguments();
        analyze(args[0], cipher_type::plain);
        analyze(args[1], t);
        analyze(args[2], t);
    }
} ANON;

extern const char str_nullif[] = "nullif";
static class CItemNullif : public CItemSubtypeFN<Item_func_nullif, str_nullif> {
    void do_analyze(Item_func_nullif *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::equal);
    }
} ANON;

template<const char *NAME>
class CItemStrconv : public CItemSubtypeFN<Item_str_conv, NAME> {
    void do_analyze(Item_str_conv *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::plain);
    }
};

extern const char str_lcase[] = "lcase";
static CItemStrconv<str_lcase> ANON;

extern const char str_ucase[] = "ucase";
static CItemStrconv<str_ucase> ANON;

template<const char *NAME>
class CItemLeafFunc : public CItemSubtypeFN<Item_func, NAME> {
    void do_analyze(Item_func *i, cipher_type t) const {}
};

extern const char str_found_rows[] = "found_rows";
static CItemLeafFunc<str_found_rows> ANON;

extern const char str_rand[] = "rand";
static CItemLeafFunc<str_rand> ANON;

template<const char *NAME>
class CItemDateExtractFunc : public CItemSubtypeFN<Item_int_func, NAME> {
    void do_analyze(Item_int_func *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            /* XXX perhaps too conservative */
            analyze(args[x], cipher_type::plain);
        }
    }
};

extern const char str_year[] = "year";
static CItemDateExtractFunc<str_year> ANON;

extern const char str_month[] = "month";
static CItemDateExtractFunc<str_month> ANON;

extern const char str_dayofmonth[] = "dayofmonth";
static CItemDateExtractFunc<str_dayofmonth> ANON;

extern const char str_unix_timestamp[] = "unix_timestamp";
static CItemDateExtractFunc<str_unix_timestamp> ANON;

extern const char str_date_add_interval[] = "date_add_interval";
static class CItemDateAddInterval : public CItemSubtypeFN<Item_date_add_interval, str_date_add_interval> {
    void do_analyze(Item_date_add_interval *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++) {
            /* XXX perhaps too conservative */
            analyze(args[x], cipher_type::plain);
        }
    }
} ANON;

template<const char *NAME>
class CItemDateNow : public CItemSubtypeFN<Item_func_now, NAME> {
    void do_analyze(Item_func_now *i, cipher_type t) const {}
};

extern const char str_now[] = "now";
static CItemDateNow<str_now> ANON;

extern const char str_utc_timestamp[] = "utc_timestamp";
static CItemDateNow<str_utc_timestamp> ANON;

extern const char str_sysdate[] = "sysdate";
static CItemDateNow<str_sysdate> ANON;

template<const char *NAME>
class CItemBitfunc : public CItemSubtypeFN<Item_func_bit, NAME> {
    void do_analyze(Item_func_bit *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::plain);
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

static class CItemLike : public CItemSubtypeFT<Item_func_like, Item_func::Functype::LIKE_FUNC> {
    void do_analyze(Item_func_like *i, cipher_type t) const {
        Item **args = i->arguments();
        if (args[1]->type() == Item::Type::STRING_ITEM) {
            string s(args[1]->str_value.ptr(), args[1]->str_value.length());
            if (s.find('%') == s.npos && s.find('_') == s.npos) {
                /* some queries actually use LIKE as an equality check.. */
                analyze(args[0], cipher_type::equal);
            } else {
                /* XXX check if pattern is one we can support? */
                analyze(args[0], cipher_type::like);
            }
        } else {
            /* we cannot support non-constant search patterns */
            for (uint x = 0; x < i->argument_count(); x++)
                analyze(args[x], cipher_type::plain);
        }
    }
} ANON;

static class CItemSP : public CItemSubtypeFT<Item_func, Item_func::Functype::FUNC_SP> {
    void error(Item_func *i) const __attribute__((noreturn)) {
        thrower() << "unsupported store procedure call " << *i;
    }

    void do_analyze(Item_func *i, cipher_type t) const __attribute__((noreturn)) { error(i); }
} ANON;

static class CItemIn : public CItemSubtypeFT<Item_func_in, Item_func::Functype::IN_FUNC> {
    void do_analyze(Item_func_in *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::equal);
    }
} ANON;

static class CItemBetween : public CItemSubtypeFT<Item_func_in, Item_func::Functype::BETWEEN> {
    void do_analyze(Item_func_in *i, cipher_type t) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            analyze(args[x], cipher_type::order);
    }
} ANON;

template<Item_sum::Sumfunctype SFT>
class CItemCount : public CItemSubtypeST<Item_sum_count, SFT> {
    void do_analyze(Item_sum_count *i, cipher_type t) const {
        if (i->has_with_distinct())
            analyze(i->get_arg(0), cipher_type::equal);
    }
};

static CItemCount<Item_sum::Sumfunctype::COUNT_FUNC> ANON;
static CItemCount<Item_sum::Sumfunctype::COUNT_DISTINCT_FUNC> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemChooseOrder : public CItemSubtypeST<Item_sum_hybrid, SFT> {
    void do_analyze(Item_sum_hybrid *i, cipher_type t) const {
        analyze(i->get_arg(0), cipher_type::order);
    }
};

static CItemChooseOrder<Item_sum::Sumfunctype::MIN_FUNC> ANON;
static CItemChooseOrder<Item_sum::Sumfunctype::MAX_FUNC> ANON;

static class CItemSumBit : public CItemSubtypeST<Item_sum_bit, Item_sum::Sumfunctype::SUM_BIT_FUNC> {
    void do_analyze(Item_sum_bit *i, cipher_type t) const {
        analyze(i->get_arg(0), cipher_type::plain);
    }
} ANON;

class CItemCharcast : public CItemSubtypeFT<Item_char_typecast, Item_func::Functype::CHAR_TYPECAST_FUNC> {
    void do_analyze(Item_char_typecast *i, cipher_type t) const {
        thrower() << "what does Item_char_typecast do?";
    }
} ANON;

class CItemRef : public CItemSubtypeIT<Item_ref, Item::Type::REF_ITEM> {
    void do_analyze(Item_ref *i, cipher_type t) const {
        if (i->ref) {
            analyze(*i->ref, t);
        } else {
            thrower() << "how to resolve Item_ref::ref?";
        }
    }
} ANON;


/*
 * Some helper functions.
 */
static void
process_select_lex(st_select_lex *select_lex, cipher_type t)
{
    auto item_it = List_iterator<Item>(select_lex->item_list);
    for (;;) {
        Item *item = item_it++;
        if (!item)
            break;

        analyze(item, t);
    }

    if (select_lex->where)
        analyze(select_lex->where, cipher_type::plain);

    if (select_lex->having)
        analyze(select_lex->having, cipher_type::plain);

    for (ORDER *o = select_lex->group_list.first; o; o = o->next)
        analyze(*o->item, cipher_type::equal);

    for (ORDER *o = select_lex->order_list.first; o; o = o->next)
        analyze(*o->item, cipher_type::order);
}

static void
process_table_list(List<TABLE_LIST> *tll)
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
            process_table_list(&t->nested_join->join_list);
            return;
        }

        if (t->on_expr)
            analyze(t->on_expr, cipher_type::plain);

        std::string db(t->db, t->db_length);
        std::string table_name(t->table_name, t->table_name_length);
        std::string alias(t->alias);

        if (t->derived) {
            st_select_lex_unit *u = t->derived;
            process_select_lex(u->first_select(), cipher_type::any);
        }
    }
}


/*
 * Test harness.
 */
extern "C" void *create_embedded_thd(int client_flag);

class mysql_thrower : public std::stringstream {
 public:
    ~mysql_thrower() __attribute__((noreturn)) {
        *this << ": " << current_thd->stmt_da->message();
        throw std::runtime_error(str());
    }
};

static void
query_analyze(const std::string &db, const std::string &q)
{
    assert(create_embedded_thd(0));
    THD *t = current_thd;
    auto ANON = cleanup([&t]() { delete t; });
    auto ANON = cleanup([&t]() { close_thread_tables(t); });
    auto ANON = cleanup([&t]() { t->cleanup_after_query(); });

    t->set_db(db.data(), db.length());
    mysql_reset_thd_for_next_command(t);

    char buf[q.size() + 1];
    memcpy(buf, q.c_str(), q.size());
    buf[q.size()] = '\0';
    size_t len = q.size();

    alloc_query(t, buf, len + 1);

    Parser_state ps;
    if (ps.init(t, buf, len))
        mysql_thrower() << "Paser_state::init";

    if (debug) cout << "input query: " << buf << endl;

    bool error = parse_sql(t, &ps, 0);
    if (error)
        mysql_thrower() << "parse_sql";

    auto ANON = cleanup([&t]() { t->end_statement(); });
    LEX *lex = t->lex;

    if (debug) cout << "parsed query: " << *lex << endl;

    /* Assumes command ordering in sql_lex.h */
    if (lex->sql_command >= SQLCOM_SHOW_DATABASES &&
        lex->sql_command <= SQLCOM_SHOW_TRIGGERS)
        return;

    /*
     * Helpful in understanding what's going on: JOIN::prepare(),
     * handle_select(), and mysql_select() in sql_select.cc.  Also
     * initial code in mysql_execute_command() in sql_parse.cc.
     */
    lex->select_lex.context.resolve_in_table_list_only(
        lex->select_lex.table_list.first);

    if (open_normal_and_derived_tables(t, lex->query_tables, 0))
        mysql_thrower() << "open_normal_and_derived_tables";

    JOIN *j = new JOIN(t, lex->select_lex.item_list,
                       lex->select_lex.options, 0);
    if (j->prepare(&lex->select_lex.ref_pointer_array,
                   lex->select_lex.table_list.first,
                   lex->select_lex.with_wild,
                   lex->select_lex.where,
                   lex->select_lex.order_list.elements
                     + lex->select_lex.group_list.elements,
                   lex->select_lex.order_list.first,
                   lex->select_lex.group_list.first,
                   lex->select_lex.having,
                   lex->proc_list.first,
                   &lex->select_lex,
                   &lex->unit))
        mysql_thrower() << "JOIN::prepare";

    if (debug) cout << "prepared query: " << *lex << endl;

    // iterate over the entire select statement..
    // based on st_select_lex::print in mysql-server/sql/sql_select.cc
    process_table_list(&lex->select_lex.top_join_list);
    process_select_lex(&lex->select_lex, cipher_type::any);
}

static string
unescape(string s)
{
    stringstream ss;

    for (;;) {
        size_t bs = s.find_first_of('\\');
        if (bs == s.npos)
            break;

        ss << s.substr(0, bs);
        s = s.substr(bs+1);

        if (s.size() == 0)
            break;
        if (s[0] == 'x' && s.size() >= 3) {
            stringstream hs(s.substr(1, 2));
            int v;
            hs >> hex >> v;
            ss << (char) v;
            s = s.substr(3);
        } else {
            ss << s[0];
            s = s.substr(1);
        }
    }
    ss << s;

    return ss.str();
}

int
main(int ac, char **av)
{
    if (ac != 3) {
        cerr << "Usage: " << av[0] << " schema-db trace-file" << endl;
        exit(1);
    }

    char dir_arg[1024];
    snprintf(dir_arg, sizeof(dir_arg), "--datadir=%s", av[1]);

    const char *mysql_av[] =
        { "progname",
          "--skip-grant-tables",
          dir_arg,
          /* "--skip-innodb", */
          /* "--default-storage-engine=MEMORY", */
          "--language=" MYSQL_BUILD_DIR "/sql/share/"
        };
    assert(0 == mysql_server_init(sizeof(mysql_av) / sizeof(mysql_av[0]),
                                  (char**) mysql_av, 0));
    assert(0 == mysql_thread_init());

    ifstream f(av[2]);
    int nquery = 0;
    int nerror = 0;
    int nskip = 0;

    for (;;) {
        string s;
        getline(f, s);
        if (f.eof())
            break;

        size_t space = s.find_first_of(' ');
        if (space == s.npos) {
            cerr << "malformed " << s << endl;
            continue;
        }

        string db = s.substr(0, space);
        string q = s.substr(space + 1);

        if (db == "") {
            nskip++;
        } else {
            string unq = unescape(q);
            try {
                query_analyze(db, unq);
            } catch (std::runtime_error &e) {
                cout << "ERROR: " << e.what() << " in query " << unq << endl;
                nerror++;
            }
        }

        nquery++;
        cout << " nquery: " << nquery
             << " nerror: " << nerror
             << " nskip: " << nskip
             << endl;
    }
}
