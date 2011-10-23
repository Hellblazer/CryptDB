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

You will need mysql-5.5.14 because we use its parser in our newer implementation:
% wget http://yuma.csail.mit.edu/mysql-5.5.14.tar.gz
% tar zxf mysql-5.5.14.tar.gz
% cp -R mysql_mods mysql-5.5.14
% cd mysql-5.5.14
% mkdir build
% cd build
% cmake -DWITH_EMBEDDED_SERVER=ON ..
% make

Now, copy config.mk.sample to config.mk and adjust the path for MYSRC
may need to sudo apt-get install libbsd-dev

------------------------------------------------------------------

To build and install CryptDB, run:

  % make
  % sudo make install

---------------------------------------------------------------

To see how to RUN CryptDB, see README.