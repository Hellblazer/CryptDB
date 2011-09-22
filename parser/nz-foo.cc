#include <iostream>
#include <parser/embedmysql.hh>

using namespace std;

static void
usage(const std::string &progname)
{
    cerr << "Usage: " << progname << " shadow_dir\n";
    exit(-1);
}

int
main(int ac, char **av)
{
    if (ac == 1)
        usage(av[0]);

    string shadow_dir(av[optind]);

    embedmysql e(shadow_dir);

}
