#include "fatal.h"

#include <string>
#include <stdio.h>
#include <bsd/string.h>

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

#include "mysql_glue.h"

class CryptItem {
 public:
    CryptItem(Item *iarg) : i(iarg)
    {
    }

    Item *
    rewrite(void)
    {
        switch (i->type()) {
        case Item::Type::FIELD_ITEM:
        {
            Item_field *ifl = (Item_field *) i;
            Item *n =
                new Item_field(0,
                               ifl->db_name,
                               strdup((std::string("anontab_") +
                                       ifl->table_name).c_str()),
                               strdup((std::string("anonfld_") +
                                       ifl->field_name).c_str()));
            n->name = i->name;
            return n;
        }

        case Item::Type::FUNC_ITEM: {
            Item_func *ifn = (Item_func *) i;

            switch (ifn->functype()) {
            case Item_func::Functype::EQ_FUNC:
            case Item_func::Functype::NE_FUNC:
            case Item_func::Functype::GT_FUNC:
            case Item_func::Functype::GE_FUNC:
            case Item_func::Functype::LT_FUNC:
            case Item_func::Functype::LE_FUNC:
            {
                Item **args = ifn->arguments();

                CryptItem a(args[0]);
                CryptItem b(args[1]);
                Item *n;
                if (ifn->functype() == Item_func::Functype::EQ_FUNC)
                    n = new Item_func_eq(a.rewrite(), b.rewrite());
                else if (ifn->functype() == Item_func::Functype::GT_FUNC)
                    n = new Item_func_gt(a.rewrite(), b.rewrite());
                else
                    fatal() << "bug";
                n->name = i->name;
                return n;
            }

            case Item_func::Functype::UNKNOWN_FUNC:
            {
                std::string name = ifn->func_name();
                Item **args = ifn->arguments();

                if (name == "+") {
                    CryptItem a(args[0]);
                    CryptItem b(args[1]);
                    Item *n = new Item_func_plus(a.rewrite(),
                                                 b.rewrite());
                    n->name = i->name;
                    return n;
                } else {
                    fatal() << "unknown function " << name;
                }
            }

            default:
                fatal() << "unknown functype " << ifn->functype();
            }
        }

        case Item::Type::COND_ITEM: {
            Item_cond *ic = (Item_cond *) i;
            switch (ic->functype()) {
            case Item_func::Functype::COND_AND_FUNC:
            case Item_func::Functype::COND_OR_FUNC:
            {
                List<Item> *arglist = ic->argument_list();
                List<Item> newlist;

                auto it = List_iterator<Item>(*arglist);
                for (;; ) {
                    Item *argitem = it++;
                    if (!argitem)
                        break;

                    CryptItem ci(argitem);
                    newlist.push_back(ci.rewrite());
                }

                Item *n;
                if (ic->functype() == Item_func::Functype::COND_AND_FUNC)
                    n = new Item_cond_and(newlist);
                else if (ic->functype() == Item_func::Functype::COND_OR_FUNC)
                    n = new Item_cond_or(newlist);
                else
                    fatal() << "bug";
                n->name = i->name;
                return n;
            }

            default:
                fatal() << "unknown cond functype " << ic->functype();
            }
        }

        case Item::Type::STRING_ITEM: {
            Item_string *is = (Item_string *) i;
            std::string s("ENCRYPTED:");
            s += std::string(is->str_value.ptr(), is->str_value.length());
            Item *n = new Item_string(strdup(s.c_str()), s.size(),
                                      is->str_value.charset());
            n->name = i->name;
            return n;
        }

        case Item::Type::INT_ITEM: {
            Item_num *in = (Item_num *) i;
            Item *n = new Item_int(in->val_int() + 1000);
            n->name = i->name;
            return n;
        }

        default:
            fatal() << "unknown type " << i->type();
        }
    }

 private:
    Item *i;
};

static void
xftest(void)
{
    THD *t = new THD;
    if (t->store_globals())
        printf("store_globals error\n");

    const char *q =
        "SELECT x.a, y.b + 2, y.c, y.cc AS ycc "
        "FROM x, y as yy1, y as yy2 "
        "WHERE x.bb = yy1.b AND yy1.k1 = yy2.k2 AND "
        "(yy2.d > 7 OR yy2.e = (3+4)) AND (yy1.f='hello') AND "
        "yy2.cc = 9";
    char buf[1024];
    strlcpy(buf, q, sizeof(buf));
    size_t len = strlen(buf);

    alloc_query(t, buf, len + 1);

    Parser_state ps;
    if (!ps.init(t, buf, len)) {
        LEX lex;
        t->lex = &lex;

        lex_start(t);
        mysql_reset_thd_for_next_command(t);

        t->set_db("", 0);

        printf("input query: %s\n", buf);
        bool error = parse_sql(t, &ps, 0);
        if (error) {
            printf("parse error: %d %d %d\n", error, t->is_fatal_error,
                   t->is_error());
            printf("parse error: h %p\n", t->get_internal_handler());
            printf("parse error: %d %s\n", t->is_error(), t->stmt_da->message());
        } else {
            //printf("command %d\n", lex.sql_command);

            // iterate over the entire select statement..
            // based on st_select_lex::print in mysql-server/sql/sql_select.cc

            // iterate over the items that select will actually return
            List<Item> new_item_list;
            auto item_it = List_iterator<Item>(lex.select_lex.item_list);
            for (;; ) {
                Item *item = item_it++;
                if (!item)
                    break;

                CryptItem ci(item);
                String s;
                Item *newitem = ci.rewrite();
                newitem->print(&s, QT_ORDINARY);
                new_item_list.push_back(newitem);
            }
            lex.select_lex.item_list = new_item_list;

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
                table_name = "anontab_" + table_name;
                alias = "anontab_" + alias;
                nt->init_one_table(strdup(db.c_str()), db.size(),
                                   strdup(
                                       table_name.c_str()), table_name.size(),
                                   strdup(alias.c_str()), t->lock_type);
                new_join_list.push_back(nt);
            }
            lex.select_lex.top_join_list = new_join_list;

            CryptItem wi(lex.select_lex.where);
            lex.select_lex.where = wi.rewrite();

            String s;
            lex.select_lex.print(t, &s, QT_ORDINARY);
            //lex.unit.print(&s, QT_ORDINARY);
            printf("output query: %s\n", s.c_ptr());
        }

        t->end_statement();
    } else {
        printf("parser init error\n");
    }

    t->cleanup_after_query();
    delete t;
}

int
main(int ac, char **av)
{
    mysql_glue_init();
    xftest();
}
