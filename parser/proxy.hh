#pragma once

#include <parser/embedmysql.hh>
#include <edb/EDBProxy.h>

class proxy {
 public:
    proxy(const std::string &shadow_dir);
    virtual ~proxy();

 private:
    embedmysql em;
    EDBProxy *edb;
};
