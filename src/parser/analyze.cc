#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <set>
#include <algorithm>

#include <stdio.h>
#include <bsd/string.h>

#include "errstream.h"
#include "mysql_glue.h"
#include "stringify.h"

#include "sql_priv.h"
#include "unireg.h"
#include "strfunc.h"
#include "sql_class.h"
#include "set_var.h"
#include "sql_base.h"
#include "rpl_handler.h"
#include "sql_parse.h"
#include "sql_plugin.h"
#include "derror.h"
#include "item.h"

#define CONCAT2(a, b)   a ## b
#define CONCAT(a, b)    CONCAT2(a, b)
#define ANON            CONCAT(__anon_id_, __LINE__)

enum class Cipher   { AES, OPE, Paillier, SWP };
enum class DataType { integer, string, decimal };
std::set<Cipher> pkCiphers = { Cipher::Paillier };

struct EncKey {
 public:
    EncKey(int i) : id(i) {}
    int id;     // XXX not right, but assume 0 is any key
};

class EncType {
 public:
    EncType(bool c = false) : isconst(c) {}
    EncType(std::vector<std::pair<Cipher, EncKey> > o)
        : onion(o), isconst(false) {}

    std::vector<std::pair<Cipher, EncKey> > onion;  // last is outermost
    bool isconst;

    /* Find a common enctype between two onions */
    bool match(const EncType &other, EncType *out) const {
        std::vector<const EncType*> v = { this, &other };
        std::sort(v.begin(), v.end(), [](const EncType *a, const EncType *b) {
                  return a->onion.size() > b->onion.size(); });

        const EncType *a = v[0];    // longer, if any
        const EncType *b = v[1];
        EncType res;

        auto ai = a->onion.begin();
        auto ae = a->onion.end();
        auto bi = b->onion.begin();
        auto be = b->onion.end();

        for (; ai != ae; ai++, bi++) {
            if (bi == be) {
                if (a->isconst || pkCiphers.find(ai->first) != pkCiphers.end()) {
                    res.onion.push_back(*ai);   // can add layers
                } else {
                    return false;
                }
            } else {
                if (ai->first != bi->first)
                    return false;

                struct EncKey k = ai->second;
                if (k.id == 0) {
                    k = bi->second;
                } else {
                    if (k.id != bi->second.id)
                        return false;
                }

                res.onion.push_back(make_pair(ai->first, k));
            }
        }

        *out = res;
        return true;
    }

    bool match(const std::vector<EncType> &encs, EncType *out) const {
        for (auto i = encs.begin(); i != encs.end(); i++)
            if (match(*i, out))
                return true;
        return false;
    }
};

class ColType {
 public:
    ColType(DataType dt) : type(dt) {}
    ColType(DataType dt, std::vector<EncType> e) : type(dt), encs(e) {}

    DataType type;
    std::vector<EncType> encs;
};

class CItemType {
 public:
    virtual Item *do_rewrite(Item *) const = 0;
    virtual ColType do_enctype(Item *) const = 0;
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

    Item *do_rewrite(Item *i) const {
        return lookup(i)->do_rewrite(i);
    }

    ColType do_enctype(Item *i) const {
        return lookup(i)->do_enctype(i);
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
static Item *
rewrite(Item *i)
{
    Item *n = itemTypes.do_rewrite(i);
    n->name = i->name;
    return n;
}

static ColType
enctype(Item *i)
{
    return itemTypes.do_enctype(i);
}


/*
 * CItemType classes for supported Items: supporting machinery.
 */
template<class T>
class CItemSubtype : public CItemType {
    virtual Item *do_rewrite(Item *i) const { return do_rewrite((T*) i); }
    virtual ColType do_enctype(Item *i) const { return do_enctype((T*) i); }
 private:
    virtual Item *do_rewrite(T *) const = 0;
    virtual ColType do_enctype(T *) const = 0;
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
static class CItemField : public CItemSubtypeIT<Item_field, Item::Type::FIELD_ITEM> {
    Item *do_rewrite(Item_field *i) const {
        return i;
    }

    ColType do_enctype(Item_field *i) const {
        /* XXX
         * need to look up current schema state.
         * return one EncType for each onion level
         * that can be exposed for this column.
         */
        return ColType(DataType::string, {
                        EncType({ make_pair(Cipher::AES, 123) }),
                        EncType({ make_pair(Cipher::OPE, 124),
                                  make_pair(Cipher::AES, 125) }),
                        EncType({ make_pair(Cipher::Paillier, 126) }),
                       });
    }
} ANON;

static class CItemString : public CItemSubtypeIT<Item_string, Item::Type::STRING_ITEM> {
    Item *do_rewrite(Item_string *i) const {
        const char *s = "some-string";
        return new Item_string(s, strlen(s), i->str_value.charset());
    }

    ColType do_enctype(Item_string *i) const {
        return ColType(DataType::string, {EncType(true)});
    }
} ANON;

static class CItemInt : public CItemSubtypeIT<Item_num, Item::Type::INT_ITEM> {
    Item *do_rewrite(Item_num *i) const {
        return new Item_int(i->val_int() + 1000);
    }

    ColType do_enctype(Item_num *i) const {
        return ColType(DataType::integer, {EncType(true)});
    }
} ANON;

static class CItemDecimal : public CItemSubtypeIT<Item_decimal, Item::Type::DECIMAL_ITEM> {
    Item *do_rewrite(Item_decimal *i) const {
        /* XXX */
        return i;
    }

    ColType do_enctype(Item_decimal *i) const {
        return DataType::decimal;
    }
} ANON;

static class CItemNeg : public CItemSubtypeFT<Item_func_neg, Item_func::Functype::NEG_FUNC> {
    Item *do_rewrite(Item_func_neg *i) const {
        rewrite(i->arguments()[0]);
        return i;
    }

    ColType do_enctype(Item_func_neg *i) const {
        return DataType::integer;   /* XXX decimal? */
    }
} ANON;

static class CItemSubselect : public CItemSubtypeIT<Item_subselect, Item::Type::SUBSELECT_ITEM> {
    Item *do_rewrite(Item_subselect *i) const {
        // XXX handle sub-selects
        return i;
    }

    ColType do_enctype(Item_subselect *i) const {
        /* XXX */
        return DataType::integer;
    }
} ANON;

template<Item_func::Functype FT, class IT>
class CItemCompare : public CItemSubtypeFT<Item_func, FT> {
    Item *do_rewrite(Item_func *i) const {
        Item **args = i->arguments();
        return new IT(rewrite(args[0]), rewrite(args[1]));
    }

    ColType do_enctype(Item_func *i) const { return DataType::integer; }
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
    Item *do_rewrite(Item_cond *i) const {
        List<Item> *arglist = i->argument_list();
        List<Item> newlist;

        auto it = List_iterator<Item>(*arglist);
        for (;; ) {
            Item *argitem = it++;
            if (!argitem)
                break;

            newlist.push_back(rewrite(argitem));
        }

        return new IT(newlist);
    }

    ColType do_enctype(Item_cond *i) const { return DataType::integer; }
};

static CItemCond<Item_func::Functype::COND_AND_FUNC, Item_cond_and> ANON;
static CItemCond<Item_func::Functype::COND_OR_FUNC,  Item_cond_or>  ANON;

template<Item_func::Functype FT>
class CItemNullcheck : public CItemSubtypeFT<Item_bool_func, FT> {
    Item *do_rewrite(Item_bool_func *i) const {
        return i;
    }

    ColType do_enctype(Item_bool_func *i) const { return DataType::integer; }
};

static CItemNullcheck<Item_func::Functype::ISNULL_FUNC> ANON;
static CItemNullcheck<Item_func::Functype::ISNOTNULL_FUNC> ANON;

static class CItemSysvar : public CItemSubtypeFT<Item_func_get_system_var, Item_func::Functype::GSYSVAR_FUNC> {
    Item *do_rewrite(Item_func_get_system_var *i) const { return i; }
    ColType do_enctype(Item_func_get_system_var *i) const {
        return DataType::integer; /* XXX ? */
    }
} ANON;

template<const char *NAME>
class CItemAdditive : public CItemSubtypeFN<Item_func_additive_op, NAME> {
    Item *do_rewrite(Item_func_additive_op *i) const {
        Item **args = i->arguments();
        return new Item_func_plus(rewrite(args[0]), rewrite(args[1]));
    }

    ColType do_enctype(Item_func_additive_op *i) const {
        /* what about date +/-? */

        Item **args = i->arguments();
        ColType t0 = enctype(args[0]);
        ColType t1 = enctype(args[0]);

        if (t0.type != DataType::integer || t1.type != DataType::integer)
            thrower() << "non-integer plus " << *args[0] << ", " << *args[1];

        EncType e;
        e.onion = {};
        if (e.match(t0.encs, &e) && e.match(t1.encs, &e))
            return ColType(DataType::integer, {e});

        e.onion = { make_pair(Cipher::Paillier, 0) };
        if (e.match(t0.encs, &e) && e.match(t1.encs, &e))
            return ColType(DataType::integer, {e});

        thrower() << "no common HOM type: " << *args[0] << ", " << *args[1];
    }
};

extern const char str_plus[] = "+";
static CItemAdditive<str_plus> ANON;

extern const char str_minus[] = "-";
static CItemAdditive<str_minus> ANON;

template<const char *NAME>
class CItemMath : public CItemSubtypeFN<Item_func, NAME> {
    Item *do_rewrite(Item_func *i) const {
        Item **args = i->arguments();
        for (uint x = 0; x < i->argument_count(); x++)
            rewrite(args[x]);
        return i; /* XXX? */
    }
    ColType do_enctype(Item_func *i) const { return DataType::integer; /* XXX? */ }
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
    Item *do_rewrite(Item_func_if *i) const {
        /* ensure args[0] is server-evaluatable */
        return i;
    }

    ColType do_enctype(Item_func_if *i) const {
        /* XXX find a common enctype between args[1] and args[2] */
        return enctype(i->arguments()[1]);
    }
} ANON;

template<const char *NAME>
class CItemStrconv : public CItemSubtypeFN<Item_str_conv, NAME> {
    Item *do_rewrite(Item_str_conv *i) const {
        return i;
    }

    ColType do_enctype(Item_str_conv *i) const {
        return DataType::string;
    }
};

extern const char str_lcase[] = "lcase";
static CItemStrconv<str_lcase> ANON;

extern const char str_ucase[] = "ucase";
static CItemStrconv<str_ucase> ANON;

template<const char *NAME>
class CItemLeafFunc : public CItemSubtypeFN<Item_func, NAME> {
    Item *do_rewrite(Item_func *i) const { return i; }
    ColType do_enctype(Item_func *i) const { return DataType::integer; }
};

extern const char str_found_rows[] = "found_rows";
static CItemLeafFunc<str_found_rows> ANON;

template<const char *NAME>
class CItemDateExtractFunc : public CItemSubtypeFN<Item_int_func, NAME> {
    Item *do_rewrite(Item_int_func *i) const { return i; }
    ColType do_enctype(Item_int_func *i) const { return DataType::integer; }
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
    Item *do_rewrite(Item_date_add_interval *i) const {
        /* XXX check if args[0] is a constant, in which case might be OK? */
        return i;
    }

    ColType do_enctype(Item_date_add_interval *i) const {
        /* XXX date? */
        return DataType::integer;
    }
} ANON;

template<const char *NAME>
class CItemDateNow : public CItemSubtypeFN<Item_func_now, NAME> {
    Item *do_rewrite(Item_func_now *i) const { return i; }
    ColType do_enctype(Item_func_now *i) const { return DataType::integer; /* XXX date? */ }
};

extern const char str_now[] = "now";
static CItemDateNow<str_now> ANON;

extern const char str_utc_timestamp[] = "utc_timestamp";
static CItemDateNow<str_utc_timestamp> ANON;

extern const char str_sysdate[] = "sysdate";
static CItemDateNow<str_sysdate> ANON;

template<const char *NAME>
class CItemBitfunc : public CItemSubtypeFN<Item_func_bit, NAME> {
    Item *do_rewrite(Item_func_bit *i) const {
        /* probably cannot do in CryptDB.. */
        return i;
    }
    ColType do_enctype(Item_func_bit *i) const { return DataType::integer; }
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
    Item *do_rewrite(Item_func_like *i) const {
        return i;
    }

    ColType do_enctype(Item_func_like *i) const { return DataType::integer; }
} ANON;

static class CItemSP : public CItemSubtypeFT<Item_func, Item_func::Functype::FUNC_SP> {
    void error(Item_func *i) const __attribute__((noreturn)) {
        thrower() << "unsupported store procedure call " << *i;
    }

    Item *do_rewrite(Item_func *i) const __attribute__((noreturn)) { error(i); }
    ColType do_enctype(Item_func *i) const __attribute__((noreturn)) { error(i); }
} ANON;

static class CItemIn : public CItemSubtypeFT<Item_func_in, Item_func::Functype::IN_FUNC> {
    Item *do_rewrite(Item_func_in *i) const {
        /* need DET */
        return i;
    }

    ColType do_enctype(Item_func_in *i) const { return DataType::integer; }
} ANON;

static class CItemBetween : public CItemSubtypeFT<Item_func_in, Item_func::Functype::BETWEEN> {
    Item *do_rewrite(Item_func_in *i) const {
        /* need OPE */
        return i;
    }

    ColType do_enctype(Item_func_in *i) const { return DataType::integer; }
} ANON;

template<Item_sum::Sumfunctype SFT>
class CItemCount : public CItemSubtypeST<Item_sum_count, SFT> {
    Item *do_rewrite(Item_sum_count *i) const {
        if (i->has_with_distinct()) {
            /* need DET.. */
        }

        return i;
    }

    ColType do_enctype(Item_sum_count *i) const { return DataType::integer; }
};

static CItemCount<Item_sum::Sumfunctype::COUNT_FUNC> ANON;
static CItemCount<Item_sum::Sumfunctype::COUNT_DISTINCT_FUNC> ANON;

template<Item_sum::Sumfunctype SFT>
class CItemChooseOrder : public CItemSubtypeST<Item_sum_hybrid, SFT> {
    Item *do_rewrite(Item_sum_hybrid *i) const {
        /* need OPE */
        return i;
    }

    ColType do_enctype(Item_sum_hybrid *i) const {
        /* OPE of whatever data type args[0] is */
        return DataType::integer;
    }
};

static CItemChooseOrder<Item_sum::Sumfunctype::MIN_FUNC> ANON;
static CItemChooseOrder<Item_sum::Sumfunctype::MAX_FUNC> ANON;

static class CItemSumBit : public CItemSubtypeST<Item_sum_bit, Item_sum::Sumfunctype::SUM_BIT_FUNC> {
    Item *do_rewrite(Item_sum_bit *i) const {
        /* might not be doable in CryptDB? */
        return i;
    }

    ColType do_enctype(Item_sum_bit *i) const { return DataType::integer; }
} ANON;

class CItemCharcast : public CItemSubtypeFT<Item_char_typecast, Item_func::Functype::CHAR_TYPECAST_FUNC> {
    Item *do_rewrite(Item_char_typecast *i) const {
        /* XXX what does this even do? */
        return i;
    }

    ColType do_enctype(Item_char_typecast *i) const {
        /* XXX? */
        return DataType::integer;
    }
} ANON;


/*
 * Test harness.
 */
static void
xftest(const std::string &db, const std::string &q)
{
    THD *t = new THD;
    if (t->store_globals())
        printf("store_globals error\n");

    char buf[q.size() + 1];
    memcpy(buf, q.c_str(), q.size());
    buf[q.size()] = '\0';
    size_t len = q.size();

    alloc_query(t, buf, len + 1);

    Parser_state ps;
    if (!ps.init(t, buf, len)) {
        LEX lex;
        t->lex = &lex;

        lex_start(t);
        mysql_reset_thd_for_next_command(t);

        t->set_db(db.data(), db.length());

        printf("input query: %s\n", buf);
        bool error = parse_sql(t, &ps, 0);
        if (error) {
            printf("parse error: %d %d %d\n", error, t->is_fatal_error, t->is_error());
            printf("parse error: h %p\n", t->get_internal_handler());
            printf("parse error: %d %s\n", t->is_error(), t->stmt_da->message());
        } else {
            //printf("command %d\n", lex.sql_command);
            cout << "parsed query: " << lex << endl;

            // iterate over the entire select statement..
            // based on st_select_lex::print in mysql-server/sql/sql_select.cc

            // iterate over the items that select will actually return
            List<Item> new_item_list;
            auto item_it = List_iterator<Item>(lex.select_lex.item_list);
            for (;; ) {
                Item *item = item_it++;
                if (!item)
                    break;

                Item *newitem = rewrite(item);
                new_item_list.push_back(newitem);
            }
            lex.select_lex.item_list = new_item_list;

            /*
             * XXX handle different joins, e.g.
             * SELECT g2_ChildEntity.g_id, IF(ai0.g_id IS NULL, 1, 0) AS albumsFirst, g2_Item.g_originationTimestamp FROM g2_ChildEntity LEFT JOIN g2_AlbumItem AS ai0 ON g2_ChildEntity.g_id = ai0.g_id INNER JOIN g2_Item ON g2_ChildEntity.g_id = g2_Item.g_id INNER JOIN g2_AccessSubscriberMap ON g2_ChildEntity.g_id = g2_AccessSubscriberMap.g_itemId ...
             */
            auto join_it = List_iterator<TABLE_LIST>(
                lex.select_lex.top_join_list);
            List<TABLE_LIST> new_join_list;
            for (;; ) {
                TABLE_LIST *t = join_it++;
                if (!t)
                    break;

                TABLE_LIST *nt = new TABLE_LIST();
                std::string db(t->db, t->db_length);
                std::string table_name(t->table_name, t->table_name_length);
                std::string alias(t->alias);

                // XXX handle sub-selects..
                nt->init_one_table(strdup(db.c_str()), db.size(),
                                   strdup(table_name.c_str()), table_name.size(),
                                   strdup(alias.c_str()), t->lock_type);
                new_join_list.push_back(nt);
            }
            lex.select_lex.top_join_list = new_join_list;
            if (lex.select_lex.where)
                lex.select_lex.where = rewrite(lex.select_lex.where);

            cout << "output query: " << lex << endl;
        }

        t->end_statement();
    } else {
        printf("parser init error\n");
    }

    t->cleanup_after_query();
    delete t;
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
        if (s[0] == 'x') {
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
    mysql_glue_init();

    for (uint nquery = 0; ; nquery++) {
        string s;
        getline(cin, s);
        if (cin.eof())
            break;

        size_t space = s.find_first_of(' ');
        if (space == s.npos) {
            cerr << "malformed " << s << endl;
            continue;
        }

        string db = s.substr(0, space);
        string q = s.substr(space + 1);

        xftest(db, unescape(q));
        cout << "nquery: " << nquery << "\n";
    }
}
