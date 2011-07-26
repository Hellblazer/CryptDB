#pragma once

#include <iostream>
#include <sstream>

enum log_group {
    log_warn,       // actual problems, as opposed to debug messages
    log_debug,      // enabled by default, to make LOG(debug) << ... easy

    // common debug messages
    log_crypto,
    log_crypto_v,
    log_crypto_data,
    log_edb,
    log_edb_v,
    log_test,
    log_am,
    log_am_v,

    // special value
    log_all,
};

class cryptdb_logger : public std::stringstream {
 public:
    cryptdb_logger(log_group g, const char *filearg, uint linearg, const char *fnarg)
        : mask(1ULL << g), file(filearg), line(linearg), func(fnarg)
    {
    }

    ~cryptdb_logger()
    {
        if (enable_mask & mask)
            std::cerr << file << ":" << line
                      << " (" << func << "): "
                      << str() << std::endl;
    }

    static void
    enable(log_group g)
    {
        if (g == log_all)
            enable_mask = ~0ULL;
        else
            enable_mask |= 1ULL << g;
    }

    static void
    disable(log_group g)
    {
        if (g == log_all)
            enable_mask = 0;
        else
            enable_mask &= ~(1ULL << g);
    }

 private:
    uint64_t mask;
    const char *file;
    uint line;
    const char *func;

    static uint64_t enable_mask;
};

#define LOG(g) (cryptdb_logger(log_ ## g, __FILE__, __LINE__, __func__))

