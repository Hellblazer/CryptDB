#pragma once

#include <sstream>
#include <string>
#include <stdexcept>

#include <mysql.h>

class embedmysql {
 public:
    embedmysql(const std::string &dir);
    virtual ~embedmysql();

    MYSQL *conn();

 private:
    MYSQL *m;
};

class mysql_thrower : public std::stringstream {
 public:
    ~mysql_thrower() __attribute__((noreturn));
};

class THD;
class LEX;

class QueryCallback {
public:
  virtual ~QueryCallback() {}
  virtual void do_callback(THD *t, LEX *lex) const = 0;
};

void
do_query_analyze(const std::string   &db,
                 const std::string   &q,
                 const QueryCallback &callback);
