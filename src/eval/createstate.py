import os
import sys

#
#  Creates state in phpbb of many registered users
#  -- avoids filling in a long registration form for every user
#
#
#  Args: nr users outputfile

header = "use phpbb; INSERT INTO activeusers VALUES ('admin', 'letmein'); \
    INSERT INTO activeusers VALUES ('anonymous', 'letmein'); \
    DROP FUNCTION IF EXISTS groupaccess;\
    CREATE FUNCTION groupaccess (auth_option_id mediumint(8), auth_role_id mediumint(8)) RETURNS bool RETURN ((auth_option_id = 14) OR (auth_role_id IN (1, 2, 4, 6, 10, 11, 12, 13, 14, 15, 17, 22, 23, 24)));\n" 

insertheader = "INSERT INTO phpbb_users (user_id, username, username_clean, user_password, group_id) VALUES ("
unamebase = "user"
uidstart = 5;
insertfooter = "'$H$9Y2okYC6esucbYl91NyweDbXP5ys2x.', 5);\n"

user_group_header1 = "INSERT INTO phpbb_user_group VALUES (2, "
user_group_header2 = "INSERT INTO phpbb_user_group VALUES (7, "
user_group_header3 = "INSERT INTO phpbb_user_group VALUES (4, "
user_group_header4 = "INSERT INTO phpbb_user_group VALUES (5, "

user_group_footer = ", 0, 0);\n"

active_users_header = "INSERT INTO pwdcryptdb__phpbb_users (username_clean, psswd) VALUES (";
active_users_footer = ", 'letmein');\n";


def main(arg):
    
    if len(arg) != 4:
        print 'wrong nr of args: python createstate.py no-users headerfile outputfile'
        return
    
    users = int(arg[1])
    filename = arg[3]
    headerfile = arg[2]
    
    f = open(headerfile, 'w')
    f.write(header)
    f.close()
    
    f = open(filename, 'w')
    
    f.write("use phpbb;")
    
    for i in range(0, users):
        userid = uidstart + i
        username = "'" + unamebase + repr(userid) + "'"
        
        # logs in users with cryptdb 
        query = active_users_header + username + active_users_footer;
        f.write(query)
        
        # inserts them into the users table
        query = insertheader + repr(userid) + ", "+ username + ", " + username + ", " + insertfooter 
        f.write(query)
    
        # inserts them into the user group table as new users -- mimicking what phpbb would do
        query = user_group_header1 + repr(userid) + user_group_footer
        f.write(query)
        
        query = user_group_header2 + repr(userid) + user_group_footer
        f.write(query)
        
          # inserts them into the user group table as new users -- mimicking what phpbb would do
        query = user_group_header3 + repr(userid) + user_group_footer
        f.write(query)
        
        query = user_group_header4 + repr(userid) + user_group_footer
        f.write(query)
        
         
        
    f.close()
    
main(sys.argv)

# failed attempts at automatically inserting private messsages
#msg_index
#cuser
#INSERT INTO phpbb_privmsgs_to (msg_id, user_id, author_id, folder_id) VALUES (msg_index, cuser, 2, -3);
#INSERT INTO phpbb_privmsgs_to (msg_id, user_id, author_id, folder_id) VALUES (msg_index, 2, 2, -2);

# INSERT INTO phpbb_privmsgs (msg_id, author_id, message_subject, message_text, to_address) VALUES
# (msg_id, 2, "hello user", "I know you are user uname", email) 



# INSERT INTO phpbb_privmsgs_to (msg_id, user_id, author_id, folder_id) VALUES (3, 6, 2, -3);
# INSERT INTO phpbb_privmsgs_to (msg_id, user_id, author_id, folder_id) VALUES (3, 2, 2, -2);

#INSERT INTO phpbb_privmsgs (msg_id, author_id, message_subject, message_text, to_address) VALUES
#(3, 2, "hello user 6", "I know you are user user 6", 'u_6'); 
