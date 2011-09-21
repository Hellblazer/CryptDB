#include <assert.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <util/errstream.hh>
#include <parser/embedmysql.hh>

using namespace std;
static bool embed_active = false;

embedmysql::embedmysql(const std::string &dir)
{
    if (!__sync_bool_compare_and_swap(&embed_active, false, true))
        fatal() << "only one embedmysql object can exist at once\n";

    char dir_arg[1024];
    snprintf(dir_arg, sizeof(dir_arg), "--datadir=%s", dir.c_str());

    const char *mysql_av[] =
        { "progname",
          "--skip-grant-tables",
          dir_arg,
          "--character-set-server=utf8",
          "--language=" MYSQL_BUILD_DIR "/sql/share/"
        };

    assert(0 == mysql_server_init(sizeof(mysql_av) / sizeof(mysql_av[0]),
                                  (char**) mysql_av, 0));
    m = mysql_init(0);

    mysql_options(m, MYSQL_OPT_USE_EMBEDDED_CONNECTION, 0);
    if (!mysql_real_connect(m, 0, 0, 0, 0, 0, 0, CLIENT_MULTI_STATEMENTS)) {
        mysql_close(m);
        fatal() << "mysql_real_connect: " << mysql_error(m);
    }
}

embedmysql::~embedmysql()
{
    mysql_close(m);
    mysql_server_end();
    assert(__sync_bool_compare_and_swap(&embed_active, true, false));
}

MYSQL *
embedmysql::conn()
{
    /*
     * Need to call mysql_thread_init() in every thread that touches
     * MySQL state.  mysql_server_init() calls it internally.  Safe
     * to call mysql_thread_init() many times.
     */
    mysql_thread_init();
    return m;
}
