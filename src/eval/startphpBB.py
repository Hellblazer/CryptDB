import sys
import os
import time

flags = "-v"
output_file = "out.html"

def prepare():
    db = "mysql -u root -pletmein -e 'DROP DATABASE cryptdb_phpbb; CREATE DATABASE cryptdb_phpbb'"
    os.system(db)
    os.putenv("CRYPTDB_USER","root")
    os.putenv("CRYPTDB_PASS","letmein")
    os.putenv("CRYPTDB_DB","cryptdb_phpbb")
    #uncomment next two lines for verbosity
    #os.putenv("CRYPTDB_LOG","11111111111111111111111111111111")
    #os.putenv("CRYPTDB_PROXY_DEBUG","true")
    #comment out next line for verbosity
    os.putenv("CRYPTDB_LOG","00000000000000000000000000000000")
    os.putenv("CRYPTDB_MODE","multi")
    os.putenv("EDBDIR","/home/cat/cryptdb/src/edb")
    os.system("rm $EDBDIR/../apps/phpBB3/config.php")
    os.system("touch $EDBDIR/../apps/phpBB3/config.php")
    os.system("chmod 666 $EDBDIR/../apps/phpBB3/config.php")
    os.system("mv $EDBDIR/../apps/phpBB3/install2 $EDBDIR/../apps/phpBB3/install")
    os.system("cp $EDBDIR/../apps/phpBB3/install/schemas/mysql_will_build_annot.sql $EDBDIR/../apps/phpBB3/install/schemas/mysql_41_schema.sql")

def proxy():
    pid = os.fork()
    if pid == 0:
        os.system("mysql-proxy --plugins=proxy --max-open-files=1024 --proxy-lua-script=$EDBDIR/../mysqlproxy/wrapper.lua --proxy-address=18.26.5.16:3307 --proxy-backend-addresses=18.26.5.16:3306")
        print(":)")
    elif pid < 0:
        print("failed to fork")
    else:
        time.sleep(1)
        db = "mysql -u root -pletmein -h 18.26.5.16 -P 3307 cryptdb_phpbb -e 'DROP FUNCTION IF EXISTS groupaccess; CREATE FUNCTION groupaccess (auth_option_id mediumint(8), auth_role_id mediumint(8)) RETURNS bool RETURN ((auth_option_id = 14) OR (auth_role_id IN (1, 2, 4, 6, 10, 11, 12, 13, 14, 15, 17, 22, 23, 24)));' "
        #db = "mysql -u root -pletmein cryptdb_phpbb2 -e 'DROP FUNCTION IF EXISTS groupaccess; CREATE FUNCTION groupaccess (auth_option_id mediumint(8), auth_role_id mediumint(8)) RETURNS bool RETURN ((auth_option_id = 14) OR (auth_role_id IN (1, 2, 4, 6, 10, 11, 12, 13, 14, 15, 17, 22, 23, 24)));'"
        os.system(db)
        #install_phpBB()


def install_phpBB():
    post = "dbms=mysqli&dbhost=127.0.0.1&dbport=3307&dbname=crypdb_phpbb&dbuser=root'&dbpasswd=letmein&table_prefix=phpbb_&admin_name=admin&admin_pass1=letmein&admin_pass2=letmein&board_email=cat_red@mit.edu&board_email2=cat_red@mit.edu"
    config = "wget "+flags+" --post-data=\'"+post+"\' \'http://"+ip+"/phpBB/install/index.php?mode=install&sub=config_file\' -O "+output_file
    os.system(config)
    post = post + "email_enable=1&smtp_delivery=0&smtp_auth=PLAIN&cookie_secure=0&force_server_vars=0&server_protocol=http://&server_name=localhost&server_port=80&script_path=/phpBB"
    create_table = "wget "+flags+" --post-data=\'"+post+"\' \'http://localhost/phpBB/install/index.php?mode=install&sub=create_table\' -O "+output_file
    os.system(create_table)

prepare()
proxy()
