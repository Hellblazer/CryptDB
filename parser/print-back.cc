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

#include <sql_select.h>
#include <sql_delete.h>
#include <sql_insert.h>
#include <sql_update.h>

#include <util/errstream.hh>
#include <util/cleanup.hh>
#include <util/rob.hh>

#include <parser/embedmysql.hh>
#include <parser/stringify.hh>

class PrintBackQueryCallback : public QueryCallback {
public:
  virtual void do_callback(THD *t, LEX *lex) const {

  }
};
static PrintBackQueryCallback s_callback;

inline static void
query_parse_and_print(const std::string &db, const std::string &q) {
  do_query_analyze(db, q, s_callback);
}

int
main(int ac, char **av)
{
    if (ac != 2) {
        cerr << "Usage: " << av[0] << " schema-db" << endl;
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
          "--character-set-server=utf8",
          "--language=" MYSQL_BUILD_DIR "/sql/share/"
        };
    assert(0 == mysql_server_init(sizeof(mysql_av) / sizeof(mysql_av[0]),
                                  (char**) mysql_av, 0));
    assert(0 == mysql_thread_init());

    for (;;) {
        string s;
        getline(cin, s);
        if (cin.eof())
            break;

        try {
            query_parse_and_print("my_db", s);
        } catch (std::runtime_error &e) {
            cout << "ERROR: " << e.what() << " in query " << s << endl;
        }
    }
}
