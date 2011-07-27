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
        host = "localhost";
        db = "cryptdbtest";
        stop_if_fail = false;
    }

    std::string user;
    std::string pass;
    std::string host;
    std::string db;

    bool stop_if_fail;
};

#define PLAIN 0

void PrintRes(ResType res);

template <int N> ResType convert(string rows[][N], int num_rows);

ResType * myExecute(EDBClient * cl, string query);

ResType * myCreate(EDBClient * cl, string annotated_query, string plain_query);
