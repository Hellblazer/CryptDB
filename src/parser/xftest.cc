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
    CryptItem(Item *iarg) : i(iarg) {}

    Item *rewrite(void) {
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
                    std::cerr << "not rewriting function " << name << std::endl;
                    return i;
                }
            }

            default:
                std::cerr << "not rewriting function " << ifn->functype() << std::endl;
                return i;
            }
        }

        default:
            std::cerr << "not rewriting type " << i->type() << std::endl;
            return i;
        }
    }

 private:
    Item *i;
};

/*
 * Traverse the Item tree.  Return values are meaningless.
 * This should turn into methods in CryptItem..
 */
static int
recurse(THD *t, Item *i)
{
    String s;
    i->print(&s, QT_ORDINARY);
    printf("recursing into %s\n", s.c_ptr());

    switch (i->type()) {
    // see types in mysql-server/sql/item.h: enum Type
    case Item::Type::COND_ITEM: {
        Item_cond *ic = (Item_cond *) i;
        switch (ic->functype()) {
        case Item_func::Functype::COND_AND_FUNC:
        case Item_func::Functype::COND_OR_FUNC:
        {
            List<Item> *arglist = ic->argument_list();

            int xr = 0;
            auto it = List_iterator<Item>(*arglist);
            for (;; ) {
                Item *argitem = it++;
                if (!argitem)
                    break;

                int xi = recurse(t, argitem);
                xr += xi;
            }
            return xr;
        }

        default:
            fatal() << "unknown cond functype " << ic->functype();
        }
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

            int xr = 0;
            xr += recurse(t, args[0]);
            xr += recurse(t, args[1]);
            return xr;
        }

        case Item_func::Functype::UNKNOWN_FUNC:
        {
            std::string name = ifn->func_name();
            Item **args = ifn->arguments();

            if (name == "+" || name == "-") {
                int xr = 0;
                xr += recurse(t, args[0]);
                xr += recurse(t, args[1]);
                return xr;
            }

            fatal() << "unknown named function " << name.c_str();
        }

        default:
            fatal() << "unknown functype " << ifn->functype();
        }
    }

    case Item::Type::STRING_ITEM: {
        Item_string *is = (Item_string *) i;
        printf("recurse: string item %s\n", is->str_value.c_ptr());
        return 0;
    }

    case Item::Type::INT_ITEM: {
        Item_num *in = (Item_num *) i;
        printf("recurse: int item %lld\n", in->val_int());
        return in->val_int();
    }

    case Item::Type::FIELD_ITEM: {
        Item_field *ifl = (Item_field *) i;
        printf("recurse: field item %s.%s.%s\n",
               ifl->db_name, ifl->table_name, ifl->field_name);
        return 0;
    }

    default:
        fatal() << "unknown item type " << i->type();
    }
    return 0;
}

static void
xftest(void)
{
    my_thread_init();
    THD *t = new THD;
    if (t->store_globals())
        printf("store_globals error\n");

    if (init_errmessage())
        printf("init_errmessage error\n");

    const char *q =
        "SELECT x.a, y.b + 2, y.c, y.cc AS ycc FROM x, y as yy1, y as yy2 WHERE x.bb = yy1.b AND yy1.k1 = yy2.k2 AND (yy2.d > 7 OR yy2.e = (3+4)) AND (yy1.f='hello') AND yy2.cc = 9";
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

        printf("q=%s\n", buf);
        bool error = parse_sql(t, &ps, 0);
        if (error) {
            printf("parse error: %d %d %d\n", error, t->is_fatal_error,
                   t->is_error());
            printf("parse error: h %p\n", t->get_internal_handler());
            printf("parse error: %d %s\n", t->is_error(), t->stmt_da->message());
        } else {
            printf("command %d\n", lex.sql_command);

            // iterate over the entire select statement..
            // based on st_select_lex::print in mysql-server/sql/sql_select.cc

            // iterate over the items that select will actually return
            List<Item> new_item_list;
            auto item_it = List_iterator<Item>(lex.select_lex.item_list);
            for (;;) {
                Item *item = item_it++;
                if (!item)
                    break;

                int x = recurse(t, item);

                CryptItem ci(item);
                String s;
                Item *newitem = ci.rewrite();
                newitem->print(&s, QT_ORDINARY);
                printf("rewrite: %s (x=%d, alias=%s)\n", s.c_ptr(), x, item->name);
                new_item_list.push_back(newitem);
            }
            lex.select_lex.item_list = new_item_list;

            //int x = recurse(t, lex.select_lex.where);
            //printf("x=%d\n", x);

            String s;
            lex.select_lex.print(t, &s, QT_ORDINARY);
            //lex.unit.print(&s, QT_ORDINARY);
            printf("reconstructed query: %s\n", s.c_ptr());
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
