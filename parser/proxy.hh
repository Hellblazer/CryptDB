#pragma once

#include <parser/embedmysql.hh>
#include <edb/EDBProxy.h>

class proxy {
 public:
    proxy(const std::string &shadow_dir);

 private:
    embedmysql em;
    EDBProxy edb;
};
