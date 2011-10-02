/*
 * TestAccessManager.h
 *
 * Created on: July 21, 2011
 *  Author: cat_red
 */

#include <edb/AccessManager.hh>
#include <test/test_utils.hh>


#ifndef TESTACCESSMANAGER_H_
#define TESTACCESSMANAGER

class TestAccessManager {
 public:
  TestAccessManager();
  virtual
    ~TestAccessManager();

  static void run(const TestConfig &tc, int argc, char ** argv);
};

#endif /* TESTACCESSMANAGER */
