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
#include <bsd/string.h>

#include "errstream.h"

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

using namespace std;

int
main(int ac, char **av)
{
    if (ac != 2) {
        cerr << "Usage: " << av[0] << " db-dir < queries-file" << endl;
        exit(1);
    }

    char dir_arg[1024];
    snprintf(dir_arg, sizeof(dir_arg), "--datadir=%s", av[1]);

    const char *mysql_av[] =
        { "progname",
          "--skip-grant-tables",
          dir_arg,
          "--language=" MYSQL_BUILD_DIR "/sql/share/"
        };
    assert(0 == mysql_server_init(sizeof(mysql_av) / sizeof(mysql_av[0]),
                                  (char**) mysql_av, 0));

    /* read queries from stdin, execute them on the embedded db */
    MYSQL *m = mysql_init(0);
    if (!m)
        fatal() << "mysql_init";

    mysql_options(m, MYSQL_OPT_USE_EMBEDDED_CONNECTION, 0);

    if (!mysql_real_connect(m, 0, 0, 0, 0, 0, 0, CLIENT_MULTI_STATEMENTS))
        fatal() << "mysql_real_connect: " << mysql_error(m);

    stringstream ss;
    vector<string> queries;

    for (;;) {
        string s;
        getline(cin, s);
        if (!cin.good())
            break;

        if (s.substr(0, 15) == "CREATE DATABASE") {
            queries.push_back(ss.str());
            ss.str("");
        }
        ss << s << endl;
    }
    queries.push_back(ss.str());

    uint ndb = 0;
    for (const string &q: queries) {
        if (mysql_query(m, q.c_str()))
            fatal() << "mysql_query: " << mysql_error(m);

        for (;;) {
            MYSQL_RES *r = mysql_store_result(m);
            if (r) {
                // cout << "got result.." << endl;
                mysql_free_result(r);
            } else if (mysql_field_count(m) == 0) {
                // cout << "rows affected: " << mysql_affected_rows(m) << endl;
            } else {
                fatal() << "could not retrieve result set";
            }

            int s = mysql_next_result(m);
            if (s > 0)
                fatal() << "mysql_next_result: " << mysql_error(m);

            if (s < 0)
                break;
        }

        ndb++;
        cout << "processed " << ndb << " query batches" << endl;
    }

    cout << "done" << endl;
    mysql_close(m);
    mysql_server_end();

    return 0;
}
