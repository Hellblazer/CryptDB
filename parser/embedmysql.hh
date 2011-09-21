#pragma once

#include <mysql.h>

class embedmysql {
 public:
    embedmysql(const std::string &dir);
    virtual ~embedmysql();

    MYSQL *conn();

 private:
    MYSQL *m;
};
