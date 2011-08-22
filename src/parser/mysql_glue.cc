#include <stdio.h>

#include "sql_priv.h"
#include "unireg.h"
#include "strfunc.h"
#include "sql_class.h"
#include "set_var.h"
#include "sql_base.h"
#include "rpl_handler.h"
#include "sql_parse.h"
#include "sql_plugin.h"
#include "derror.h"
#include "init.h"

#include "mysql_glue.hh"

void
mysql_glue_init(void)
{
    system_charset_info = &my_charset_utf8_general_ci;
    global_system_variables.character_set_client = system_charset_info;
    table_alias_charset = &my_charset_bin;

    pthread_key_t dummy;
    if (pthread_key_create(&dummy, 0) ||
        pthread_key_create(&THR_THD, 0) ||
        pthread_key_create(&THR_MALLOC, 0))
        printf("pthread_key_create error\n");

    sys_var_init();
    unireg_init(SPECIAL_ENGLISH);
    lex_init();
    item_create_init();
    item_init();

    my_init();
    mdl_init();
    table_def_init();
    randominit(&sql_rand, 0, 0);
    delegates_init();
    init_tmpdir(&mysql_tmpdir_list, 0);

    default_charset_info =
        get_charset_by_csname("utf8", MY_CS_PRIMARY, MYF(MY_WME));
    global_system_variables.collation_server         = default_charset_info;
    global_system_variables.collation_database       = default_charset_info;
    global_system_variables.collation_connection     = default_charset_info;
    global_system_variables.character_set_results    = default_charset_info;
    global_system_variables.character_set_client     = default_charset_info;
    global_system_variables.character_set_filesystem = default_charset_info;

    my_default_lc_messages = my_locale_by_name("en_US");
    global_system_variables.lc_messages = my_default_lc_messages;

    opt_ignore_builtin_innodb = true;
    int plugin_ac = 1;
    char *plugin_av = (char *) "x";
    plugin_init(&plugin_ac, &plugin_av, 0);
    init_errmessage();
    my_thread_init();
}
