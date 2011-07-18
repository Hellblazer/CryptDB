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

/*
 * Traverse the Item tree.  Return values are meaningless.
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
        "SELECT x.a, y.b + 2, y.c, y.cc AS ycc FROM x, y WHERE x.bb = y.b AND (y.d > 7 OR y.e = (3+4)) AND (y.f='hello') AND y.cc = 9";
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
            auto item_it = List_iterator<Item>(lex.select_lex.item_list);
            for (;; ) {
                Item *item = item_it++;
                if (!item)
                    break;

                int x = recurse(t, item);
                printf("x=%d\n", x);
            }

            int x = recurse(t, lex.select_lex.where);
            printf("x=%d\n", x);

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
    system_charset_info = &my_charset_utf8_general_ci;
    global_system_variables.character_set_client = system_charset_info;
    table_alias_charset = &my_charset_bin;

    pthread_key_t dummy;
    if (pthread_key_create(&dummy, 0) ||
        pthread_key_create(&THR_THD, 0) ||
        pthread_key_create(&THR_MALLOC, 0))
        printf("pthread_key_create error\n");

    sys_var_init();
    lex_init();
    item_create_init();
    item_init();

    my_init();
    mdl_init();
    table_def_init();
    randominit(&sql_rand, 0, 0);
    delegates_init();
    init_tmpdir(&mysql_tmpdir_list, 0);

    default_charset_info =
        get_charset_by_csname("utf8", MY_CS_PRIMARY, MYF(MY_WME));
    global_system_variables.collation_server         = default_charset_info;
    global_system_variables.collation_database       = default_charset_info;
    global_system_variables.collation_connection     = default_charset_info;
    global_system_variables.character_set_results    = default_charset_info;
    global_system_variables.character_set_client     = default_charset_info;
    global_system_variables.character_set_filesystem = default_charset_info;

    my_default_lc_messages = my_locale_by_name("en_US");
    global_system_variables.lc_messages = my_default_lc_messages;

    opt_ignore_builtin_innodb = true;
    int plugin_ac = 1;
    char *plugin_av = (char *) "x";
    plugin_init(&plugin_ac, &plugin_av, 0);

    //const char *engine = "MEMORY";
    //LEX_STRING name = { (char *) engine, strlen(engine) };
    //plugin_ref plugin = ha_resolve_by_name(0, &name);
    //global_system_variables.table_plugin = plugin;

    xftest();
}
