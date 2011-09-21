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
static inline List_noparen<T>&
noparen(List<T> &l)
{
    return *(List_noparen<T>*) (&l);
}

template<class T>
static inline ostream&
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
static inline ostream&
operator<<(ostream &out, List<T> &l)
{
    return out << "(" << noparen(l) << ")";
}

static inline ostream&
operator<<(ostream &out, SELECT_LEX &select_lex)
{
    // TODO(stephentu): mysql's select print is
    // missing some parts, like procedure, into outfile,
    // for update, and lock in share mode
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

static ostream&
operator<<(ostream &out, LEX &lex)
{
    String s;
    THD *t = current_thd;

    switch (lex.sql_command) {
    case SQLCOM_SELECT:
        // out << lex.select_lex;
        out << lex.unit;
        break;

    case SQLCOM_UPDATE:
    case SQLCOM_UPDATE_MULTI:
        {
            TABLE_LIST tl;
            st_nested_join nj;
            tl.nested_join = &nj;
            nj.join_list = lex.select_lex.top_join_list;
            tl.print(t, &s, QT_ORDINARY);
            out << "update " << s;
        }

        if (lex.query_tables->lock_type == TL_WRITE_LOW_PRIORITY) {
            out << " low_priority ";
        }

        if (lex.ignore) {
            out << " ignore ";
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

        if (lex.sql_command == SQLCOM_UPDATE) {
            if (lex.select_lex.order_list.elements) {
                String s0;
                lex.select_lex.print_order(&s0, lex.select_lex.order_list.first,
                                           QT_ORDINARY);
                out << " order by " << s0;
            }

            {
                String s0;
                lex.select_lex.print_limit(t, &s0, QT_ORDINARY);
                out << s0;
            }
        }
        break;

    case SQLCOM_INSERT:
    case SQLCOM_INSERT_SELECT:
    case SQLCOM_REPLACE:
    case SQLCOM_REPLACE_SELECT:
        {
            bool is_insert =
                lex.sql_command == SQLCOM_INSERT ||
                lex.sql_command == SQLCOM_INSERT_SELECT;
            bool no_select =
                lex.sql_command == SQLCOM_INSERT ||
                lex.sql_command == SQLCOM_REPLACE;
            const char *cmd = is_insert ? "insert" : "replace";
            out << cmd << " ";

            switch (lex.query_tables->lock_type) {
            case TL_WRITE_LOW_PRIORITY:
                out << "low_priority ";
                break;
            case TL_WRITE:
                out << "high_priority ";
                break;
            case TL_WRITE_DELAYED:
                out << "delayed ";
                break;
            default:
                ; // no-op
                break;
            }

            if (lex.ignore) {
                out << "ignore ";
            }

            lex.query_tables->print(t, &s, QT_ORDINARY);
            out << "into " << s;
            if (lex.field_list.head())
                out << " " << lex.field_list;
            if (no_select) {
                if (lex.many_values.head())
                    out << " values " << noparen(lex.many_values);
            } else {
                out << " " << lex.select_lex;
            }
            if (is_insert && lex.duplicates == DUP_UPDATE) {
                out << " on duplicate key update ";
                auto ii = List_iterator<Item>(lex.update_list);
                auto iv = List_iterator<Item>(lex.value_list);
                for (bool first = true;; first = false) {
                    Item *i = ii++;
                    Item *v = iv++;
                    if (!i || !v)
                        break;
                    if (!first)
                        out << ", ";
                    out << *i << "=" << *v;
                }
            }
        }
        break;

    case SQLCOM_DELETE:
    case SQLCOM_DELETE_MULTI:
        out << "delete ";

        if (lex.query_tables->lock_type == TL_WRITE_LOW_PRIORITY) {
            out << "low_priority ";
        }

        if (lex.select_lex.options & OPTION_QUICK) {
            out << "quick ";
        }

        if (lex.ignore) {
            out << "ignore ";
        }

        if (lex.sql_command == SQLCOM_DELETE) {
            lex.query_tables->print(t, &s, QT_ORDINARY);
            out << "from " << s;
            if (lex.select_lex.where)
                out << " where " << *lex.select_lex.where;
            if (lex.select_lex.order_list.elements) {
                String s0;
                lex.select_lex.print_order(&s0, lex.select_lex.order_list.first,
                                           QT_ORDINARY);
                out << " order by " << s0;
            }
            {
                String s0;
                lex.select_lex.print_limit(t, &s0, QT_ORDINARY);
                out << s0;
            }
        } else {
            TABLE_LIST *tbl = lex.auxiliary_table_list.first;
            for (bool f = true; tbl; tbl = tbl->next_local, f = false) {
                String s0;
                tbl->print(t, &s0, QT_ORDINARY);
                out << (f ? "" : ", ") << s0;
            }
            out << " from ";

            {
                String s0;
                TABLE_LIST tl;
                st_nested_join nj;
                tl.nested_join = &nj;
                nj.join_list = lex.select_lex.top_join_list;
                tl.print(t, &s0, QT_ORDINARY);
                out << s0;
            }

            if (lex.select_lex.where)
                out << " where " << *lex.select_lex.where;
        }
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
