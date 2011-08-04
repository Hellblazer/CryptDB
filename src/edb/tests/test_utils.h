/*
 * test_utils.h
 *
 * Created on: Jul 18. 2011
 *   Author: cat_red
 */

#pragma once
#include <string>
#include "EDBClient.h"

class TestConfig {
 public:
    TestConfig() {
        user = "root";
        pass = "letmein";
        host = "127.0.0.1";
        db = "cryptdbtest";
	port = 3307;
        stop_if_fail = false;
    }

    std::string user;
    std::string pass;
    std::string host;
    std::string db;
    uint port;

    bool stop_if_fail;
};

#define PLAIN 0

void PrintRes(const ResType &res);

template <int N> ResType convert(string rows[][N], int num_rows);

ResType myExecute(EDBClient * cl, string query);

ResType myCreate(EDBClient * cl, string annotated_query, string plain_query);

static inline void
assert_res(const ResType &r, const char *blah)
{
    assert_s(r.ok, blah);
}

static inline bool
match(const ResType &res, const ResType &expected)
{
    return res.names == expected.names && res.rows == expected.rows;
}

