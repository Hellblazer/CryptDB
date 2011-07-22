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

#include "mysql_glue.h"

static void
parse(const char *q)
{
    THD *t = new THD;
    if (t->store_globals())
        printf("store_globals error\n");

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
    if (ac != 2) {
        printf("Usage: %s query\n", av[0]);
        exit(1);
    }

    mysql_glue_init();
    const char *q = av[1];
    parse(q);
}
