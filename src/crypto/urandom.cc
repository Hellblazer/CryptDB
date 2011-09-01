#include <assert.h>
#include <string.h>
#include <sys/fcntl.h>
#include <crypto/prng.hh>
#include <util/errstream.hh>

using namespace std;

urandom::urandom()
    : f("/dev/urandom")
{
    if (f.fail())
        thrower() << "cannot open /dev/urandom: " << strerror(errno);
}

string
urandom::rand_bytes(size_t nbytes)
{
    char buf[nbytes];
    f.read(buf, nbytes);
    return string(buf, nbytes);
}

void
urandom::seed(const std::string &rnd)
{
    f << rnd;
}
