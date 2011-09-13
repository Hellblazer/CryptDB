Packages needed for Ubuntu:

  % apt-get install liblua5.1-0-dev libntl-dev libmysqlclient-dev libssl-dev

You will need to install mysql-proxy from source, because
versions prior to 0.9.0 have various bugs that break CryptDB.
See ../src/mysqlproxy/README.txt for details.

You will need g++ version 4.6 or higher to build CryptDB.  Ubuntu Oneiric
(11.10) includes g++ 4.6.1.  For earlier versions of Ubuntu, consider:

  % apt-add-repository ppa:ubuntu-toolchain-r/test
  % apt-get update
  % apt-get install gcc-4.6 g++-4.6

To build and install CryptDB, run in src/edb:

  % make
  % sudo make install

