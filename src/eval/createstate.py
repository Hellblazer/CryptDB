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
uidstart = 100;
insertfooter = "'$H$9Y2okYC6esucbYl91NyweDbXP5ys2x.', 5);\n"

user_group_header1 = "INSERT INTO phpbb_user_group VALUES (2, "
user_group_header2 = "INSERT INTO phpbb_user_group VALUES (7, "
user_group_header3 = "INSERT INTO phpbb_user_group VALUES (4, "
user_group_header4 = "INSERT INTO phpbb_user_group VALUES (5, "

user_group_footer = ", 0, 0);\n"

active_users_header = "INSERT INTO pwdcryptdb__phpbb_users (username_clean, psswd) VALUES (";
active_users_footer = ", 'letmein');\n";



midstart = 100;

pm_header = "INSERT INTO phpbb_privmsgs (msg_id, root_level, author_id, icon_id, author_ip, message_time, enable_bbcode, enable_smilies, enable_magic_url, enable_sig, message_subject, message_text, message_attachment, bbcode_bitfield, bbcode_uid, to_address, bcc_address, message_reported) VALUES ("
pm_middle = ", 0, '"
pm_footer = "', 0, '170.0.0.1', 1314137570, 1, 1, 1, 1, 'subject', 'this is the text of the message.  this is very exciting.  and uncapitalized', 0, '', '', 'u_2', '', 0);\n"

pm_to_send_header = "INSERT INTO phpbb_privmsgs_to (msg_id, user_id, author_id, folder_id, pm_new, pm_unread, pm_forwarded) VALUES ("
pm_to_send_middle = ", 2, "
pm_to_send_footer =", -3, 1, 1, 0);\n"

pm_rec_update = "UPDATE phpbb_users SET user_new_privmsg = user_new_privmsg + 1, user_unread_privmsg = user_unread_privmsg + 1, user_last_privmsg = 1314137570 WHERE user_id = 2;\n"

pm_to_rec_header = "INSERT INTO phpbb_privmsgs_to  (msg_id, user_id, author_id, folder_id, pm_new, pm_unread, pm_forwarded) VALUES (82, "
pm_to_rec_middle = ", "
pm_to_rec_footer = ", -2, 0, 0, 0);\n"

pm_send_update = "UPDATE phpbb_users SET user_lastpost_time = 1314137570 WHERE user_id = "




def main(arg):
    
    if len(arg) != 5:
        print 'wrong nr of args: python createstate.py no-users no-messages headerfile outputfile'
        return
    
    users = int(arg[1])
    messages = int(arg[2])
    filename = arg[4]
    headerfile = arg[3]
    
    f = open(headerfile, 'w')
    f.write(header)
    f.close()
    
    f = open(filename, 'w')
    
    #f.write("use phpbb;")
    
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

    for i in range(0, messages):
        msg_id = midstart + i
        author_id = str((msg_id % users) + uidstart)
        

        query = pm_header + str(msg_id) + pm_middle + author_id + pm_footer
        f.write(query)
        
        query = pm_to_send_header + str(msg_id) + pm_to_send_middle + str(msg_id) + pm_to_send_footer
        f.write(query)

        f.write(pm_rec_update)

        query = pm_to_rec_header + author_id + pm_to_rec_middle + author_id + pm_to_rec_footer
        f.write(query)

        query = pm_send_update + author_id + ";\n"
        f.write(query)

    f.close()

    os.system("mysql -u root -pletmein -h 127.0.0.1 -P 3307 cryptdb_phpbb < "+filename)
    
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






