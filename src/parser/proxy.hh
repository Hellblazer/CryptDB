#pragma once

#include <parser/embedmysql.hh>

class proxy {
 public:
    proxy(const std::string &shadow_dir);

 private:
    embedmysql em;
};
