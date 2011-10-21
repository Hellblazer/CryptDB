#include <cstdlib>
#include <cstdio>
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

#include <edb/Connect.hh>

#include <unistd.h>

#include <parser/cdb_rewrite.hh>

#include <readline/readline.h>
#include <readline/history.h>

#include <parser/embedmysql.hh>
#include <parser/stringify.hh>

#include <util/errstream.hh>

using namespace std;

static inline string user_homedir() {
    return getenv("HOME");
}

static inline string user_histfile() {
    return user_homedir() + "/.cryptdb-history";
}

static void __write_history() {
    write_history(user_histfile().c_str());
}

int
main(int ac, char **av)
{
    if (ac != 3) {
        cerr << "Usage: " << av[0] << " schema-db db " << endl;
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
    assert(0 == mysql_library_init(sizeof(mysql_av) / sizeof(mysql_av[0]),
            (char**) mysql_av, 0));
    assert(0 == mysql_thread_init());

    using_history();
    read_history(user_histfile().c_str());
    atexit(__write_history);

    string db(av[2]);
    Rewriter r(db);
    r.setMasterKey("2392834");

    cerr << "connecting to localhost db cryptdbtest user root pass letmein" << "\n";
    Connect conn("localhost", "root", "letmein", "cryptdbtest");
    DBResult * dbres;

    for (;;) {
        char *input = readline("CryptDB=# ");

        if (!input) break;

        string q(input);
        if (q.empty()) continue;

        if (q == "\\q") {
            cerr << "Goodbye!\n";
            break;
        }
        add_history(input);
        string new_q;
        try {
            Analysis analysis;
            new_q = r.rewrite(q, analysis);
            cout << "SUCCESS: " << new_q << endl;
	    conn.execute(new_q, dbres);
	    ResType res = dbres->unpack();
	    if (!res.ok) {
		cerr << "issue with query \n";
		continue;
	    }
	    ResType dec_res = r.decryptResults(res, analysis);
	    cerr << "decrypted results are: \n"; printRes(dec_res);

        } catch (std::runtime_error &e) {
            cout << "Unexpected Error: " << e.what() << " in query " << q << endl;
        } catch (CryptDBError &e) {
            cout << "Interal Error: " << e.msg << " in query " << q << endl;
        }
    }
}
