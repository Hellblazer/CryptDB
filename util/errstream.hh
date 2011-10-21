#pragma once

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

typedef struct CryptDBError {
 public:
    CryptDBError(const std::string &m) : msg(m)
    {
    }
    std::string msg;
} CryptDBError;

class fatal : public std::stringstream {
 public:
    ~fatal() __attribute__((noreturn)) {
        std::cerr << str() << std::endl;
        exit(-1);
    }
};

class cryptdb_err : public std::stringstream {
 public:
    ~cryptdb_err() throw (CryptDBError) {
        std::cerr << str() << std::endl;
        throw CryptDBError(str());
    }
};

class thrower : public std::stringstream {
 public:
    ~thrower() __attribute__((noreturn)) {
        throw std::runtime_error(str());
    }
};
