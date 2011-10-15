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
#include <stdio.h>

#include <parser/cdb_rewrite.hh>



#include <parser/embedmysql.hh>
#include <parser/stringify.hh>

#include <util/errstream.hh>



using namespace std;

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
            "--character-set-server=utf8",
            "--language=" MYSQL_BUILD_DIR "/sql/share/"
    };
    assert(0 == mysql_library_init(sizeof(mysql_av) / sizeof(mysql_av[0]),
            (char**) mysql_av, 0));
    assert(0 == mysql_thread_init());

    ifstream f(av[2]);
    int nquery = 0;
    int nerror = 0;
    int nskip = 0;

    Rewriter * r = NULL;
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
        cerr << "db: " << db << "\n";
        if (!r) {

	    r = new Rewriter(db);
	    r->setMasterKey("2392834");
	    
	};
        string q = s.substr(space + 1);
        cerr << "q: " << q << "\n";
        string new_q;
        if (db == "") {
            nskip++;
        } else {
            try {
                cerr << "before query " << "\n";
                ReturnMeta rmeta;
                new_q = r->rewrite(q, rmeta);
            } catch (std::runtime_error &e) {
                cout << "ERROR: " << e.what() << " in query " << q << endl;
                nerror++;
            }
            cerr << "resulting query: " << new_q << " \n";
        }

        nquery++;
        if (!(nquery % 100))
            cout << " nquery: " << nquery
            << " nerror: " << nerror
            << " nskip: " << nskip
            << endl;
    }
}
