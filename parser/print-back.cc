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
#include <parser/stringify.hh>

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
query_parse_and_print(const std::string &db, const std::string &q)
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

    cout << "input query: " << buf << endl;

    bool error = parse_sql(t, &ps, 0);
    if (error)
        mysql_thrower() << "parse_sql";

    auto ANON = cleanup([&t]() { t->end_statement(); });
    LEX *lex = t->lex;

    cout << "parsed query: " << *lex << endl;
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
            query_parse_and_print("dbtest", s);
        } catch (std::runtime_error &e) {
            cout << "ERROR: " << e.what() << " in query " << s << endl;
        }
    }
}
