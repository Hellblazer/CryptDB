/*
 * test_utils.h
 *
 * Created on: Jul 18. 2011
 *   Author: cat_red
 */

#pragma once
#include <string>
#include <assert.h>
#include "EDBClient.h"

class TestConfig {
 public:
    TestConfig() {
    	// default values
        user = "root";
        pass = "letmein";
        host = "127.0.0.1";
        db   = "cryptdbtest";
        port = 3306;
        stop_if_fail = false;

        // hack to find current dir
        char buf[1024];
        ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        assert(n > 0);
        buf[n] = '\0';

        std::string s(buf, n);
        auto i = s.find_last_of('/');
        assert(i != s.npos);

        edbdir = s.substr(0, i) + "/..";
    }

    std::string user;
    std::string pass;
    std::string host;
    std::string db;
    uint port;

    bool stop_if_fail;

    std::string edbdir;
};

#define PLAIN 0

void PrintRes(const ResType &res);

template <int N> ResType convert(string rows[][N], int num_rows);

ResType myExecute(EDBClient * cl, string query);

ResType myCreate(EDBClient * cl, string annotated_query, string plain_query);

static inline void
assert_res(const ResType &r, const char *msg)
{
    assert_s(r.ok, msg);
}

static inline bool
match(const ResType &res, const ResType &expected)
{
    return res.names == expected.names && res.rows == expected.rows;
}

