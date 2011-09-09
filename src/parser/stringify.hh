#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>

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

using namespace std;

static inline ostream&
operator<<(ostream &out, String &s)
{
    return out << string(s.ptr(), s.length());
}

static inline ostream&
operator<<(ostream &out, Item &i)
{
    String s;
    i.print(&s, QT_ORDINARY);
    return out << s;
}

template<class T>
class List_noparen: public List<T> {};

template<class T>
static List_noparen<T>&
noparen(List<T> &l)
{
    return *(List_noparen<T>*) (&l);
}

template<class T>
static ostream&
operator<<(ostream &out, List_noparen<T> &l)
{
    bool first = true;
    for (auto it = List_iterator<T>(l);;) {
        T *i = it++;
        if (!i)
            break;

        if (!first)
            out << ", ";
        out << *i;
        first = false;
    }
    return out;
}

template<class T>
static ostream&
operator<<(ostream &out, List<T> &l)
{
    return out << "(" << noparen(l) << ")";
}

static inline ostream&
operator<<(ostream &out, SELECT_LEX &select_lex)
{
    String s;
    THD *t = current_thd;
    select_lex.print(t, &s, QT_ORDINARY);
    return out << s;
}

static inline ostream&
operator<<(ostream &out, SELECT_LEX_UNIT &select_lex_unit)
{
    String s;
    select_lex_unit.print(&s, QT_ORDINARY);
    return out << s;
}

static inline ostream&
operator<<(ostream &out, LEX &lex)
{
    String s;
    THD *t = current_thd;

    switch (lex.sql_command) {
    case SQLCOM_SELECT:
        out << lex.select_lex;
        break;

    case SQLCOM_UPDATE:
        {
            TABLE_LIST tl;
            st_nested_join nj;
            tl.nested_join = &nj;
            nj.join_list = lex.select_lex.top_join_list;
            tl.print(t, &s, QT_ORDINARY);
            out << "update " << s;
        }

        {
            auto ii = List_iterator<Item>(lex.select_lex.item_list);
            auto iv = List_iterator<Item>(lex.value_list);
            for (bool first = true;; first = false) {
                Item *i = ii++;
                Item *v = iv++;
                if (!i || !v)
                    break;
                if (first)
                    out << " set ";
                else
                    out << ", ";
                out << *i << "=" << *v;
            }
        }

        if (lex.select_lex.where)
            out << " where " << *lex.select_lex.where;
        // handle order, limit (see st_select_lex::print)
        break;

    case SQLCOM_INSERT:
        {
            lex.query_tables->print(t, &s, QT_ORDINARY);
            out << "insert into " << s;
        }
        if (lex.field_list.head())
            out << " " << lex.field_list;
        if (lex.many_values.head())
            out << " values " << noparen(lex.many_values);
        break;

    case SQLCOM_DELETE:
        {
            lex.query_tables->print(t, &s, QT_ORDINARY);
            out << "delete from " << s;
        }
        if (lex.select_lex.where)
            out << " where " << *lex.select_lex.where;
        break;

    case SQLCOM_CREATE_TABLE:
    case SQLCOM_DROP_TABLE:
    case SQLCOM_BEGIN:
    case SQLCOM_COMMIT:
    case SQLCOM_ROLLBACK:
    case SQLCOM_SET_OPTION:
    case SQLCOM_SHOW_DATABASES:
    case SQLCOM_SHOW_TABLES:
    case SQLCOM_SHOW_FIELDS:
    case SQLCOM_SHOW_KEYS:
    case SQLCOM_SHOW_VARIABLES:
    case SQLCOM_SHOW_STATUS:
    case SQLCOM_SHOW_COLLATIONS:
    case SQLCOM_CHANGE_DB:  /* for analysis, assume we never change DB? */
        /* placeholders to make analysis work.. */
        out << ".. type " << lex.sql_command << " query ..";
        break;

    default:
        for (stringstream ss;;) {
            ss << "unhandled sql command " << lex.sql_command;
            throw std::runtime_error(ss.str());
        }
    }

    return out;
}
