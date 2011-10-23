/*
 * Translator.cpp
 *
 *  Created on: Aug 13, 2010
 *      Author: raluca
 */

#include <edb/Translator.hh>
#include <util/cryptdb_log.hh>


using namespace std;


string
fullName(string field, string name)
{
    if (isTableField(field)) {
        return field;
    } else {
        return name + "." + field;
    }
}

bool
isTableField(string token)
{
    size_t pos = token.find(".");

    if (pos == string::npos) {
        return false;
    } else {
        return true;
    }
}


string
anonymizeTableName(unsigned int tableNo, string tableName, bool multiPrinc)
{
    if (!multiPrinc) {
        return string("table") + strFromVal((uint32_t)tableNo);
    } else {
        return tableName;
    }
}

string
anonymizeFieldName(unsigned int index, onion o, string origname, bool multiPrinc)
{
    
    switch (o) {
    case oDET: {
        if (multiPrinc) {
            return origname;
        } else {
            return string("field") + strFromVal(index) + "DET";
        }
    }
    case oOPE: {return string("field") + strFromVal(index) + "OPE"; }
    case oAGG: {return string("field") + strFromVal(index) + "AGG"; }
    case oSWP: {return string("field") + strFromVal(index) + "SWP"; }
    default: {assert_s(false, "invalid onion in anonymizeFieldName"); }
    }

    assert_s(false, "invalid control path in anonymizeFieldName");
    return "";
}

string
anonFieldNameForDecrypt(FieldMetadata * fm)
{

    if (!fm->isEncrypted) {
        return fm->fieldName;
    }
    if (fm->INCREMENT_HAPPENED) {
        return fm->anonFieldNameAGG;
    }
    return fm->anonFieldNameDET;
}

bool
FieldMetadata::exists(const string &val)
{
    return (val.length() > 0);
}


string
processInsert(string field, string table, FieldMetadata * fm, TableMetadata * tm)
{

    if (!fm->isEncrypted) {
        return field;
    }
    //field is encrypted

    string res = "";
    if (fm->type == TYPE_INTEGER) {
        res =  fm->anonFieldNameDET;

        if (fm->has_ope) {
            res += +", " + fm->anonFieldNameOPE;
        }
        if (fm->has_agg) {
            res +=  ", " +fm->anonFieldNameAGG;
        }
    } else {
        if (fm->type == TYPE_TEXT) {
            res =   " " + fm->anonFieldNameDET;
            if (fm->has_ope) {
                res += ",  " + fm->anonFieldNameOPE;
            }
            if (fm->has_search) {
                res += ", " + fm->anonFieldNameSWP;
            }
        } else {
            assert_s(false, "invalid type");
        }
    }

    if (fm->has_salt) {
        res += ", " + fm->salt_name;
    }

    return res;
}

string
nextAutoInc(map<string, unsigned int > & autoInc, string fullname)
{
    string val;
    if (autoInc.find(fullname) == autoInc.end()) {
        val = "1";
        autoInc[fullname] = 1;
    } else {
        autoInc[fullname] += 1;
        val = strFromVal(autoInc[fullname]);
    }

    return val;
}

string
getFieldName(FieldMetadata *fm)
{
    if (fm->isEncrypted) {
        return fm->anonFieldNameDET;
    } else {
        return fm->fieldName;
    }
}


string
processCreate(fieldType type, string fieldName, unsigned int index,
              TableMetadata * tm, FieldMetadata * fm, bool multiPrinc)
throw (CryptDBError)
{

    string res = "";

    switch (type) {
    case TYPE_INTEGER: {

        if (fm->isEncrypted) {
            // create field for SECLEVEL::DET encryption
            string anonFieldNameDET = anonymizeFieldName(index, oDET,
                                                         fieldName, multiPrinc);

            tm->fieldNameMap[anonFieldNameDET] = fieldName;
            fm->anonFieldNameDET = anonFieldNameDET;

            res = res  + anonFieldNameDET + " "+ TN_I64;

            if (fm->has_ope) {
                //create field for OPE encryption
                string anonFieldNameOPE = anonymizeFieldName(index, oOPE,
                                                             fieldName, multiPrinc);

                tm->fieldNameMap[anonFieldNameOPE] = fieldName;

                fm->anonFieldNameOPE = anonFieldNameOPE;

                res = res + ", " + anonFieldNameOPE + " "+ TN_I64;
            } else {
                fm->anonFieldNameOPE = "";
            }

            if (fm->has_agg) {
                string anonFieldNameAGG = anonymizeFieldName(index, oAGG,
                                                             fieldName, multiPrinc);
                fm->anonFieldNameAGG = anonFieldNameAGG;

                res = res + ", " + anonFieldNameAGG + "  "+TN_HOM+" ";
            } else {
                fm->anonFieldNameAGG = "";
            }

            if (fm->has_salt) {
                string fieldsalt = getFieldSalt(index, tm->anonTableName);
                res += ", " + fieldsalt + " " + TN_SALT;
                fm->salt_name = fieldsalt;
            }

            fm->has_search = false;

            break;
        }
        else {
            // create field for SECLEVEL::DET encryption
            fm->fieldName = fieldName;

            tm->fieldNameMap[fieldName] = fieldName;

            res = res  + fieldName + " "+ TN_I32;

            break;

        }
    }
    case TYPE_TEXT: {

        if (fm->isEncrypted) {
            string anonFieldNameDET = anonymizeFieldName(index, oDET,
                                                         fieldName, multiPrinc);
            tm->fieldNameMap[anonFieldNameDET] = fieldName;
            fm->anonFieldNameDET = anonFieldNameDET;

            res = res + " " + anonFieldNameDET + "  "+TN_TEXT+" ";

            if (fm->has_ope) {
                string anonFieldNameOPE = anonymizeFieldName(index, oOPE,
                                                             fieldName, multiPrinc);

                tm->fieldNameMap[anonFieldNameOPE] = fieldName;
                fm->anonFieldNameOPE = anonFieldNameOPE;

                res = res  + ", " + anonFieldNameOPE + " "+ TN_I64;

            } else {
                fm->anonFieldNameOPE = "";
            }

            fm->anonFieldNameAGG = "";
            fm->has_agg = false;

            if (fm->has_search) {
                fm->anonFieldNameSWP = anonymizeFieldName(index, oSWP,
                                                          fieldName, multiPrinc);

                res = res + ", " + fm->anonFieldNameSWP + "  "+TN_TEXT+" ";
            } else {
                fm->anonFieldNameSWP = "";
            }

            if (fm->has_salt) {
                string fieldsalt = getFieldSalt(index, tm->anonTableName);
                res += ", " + fieldsalt + " " + TN_SALT;
                fm->salt_name = fieldsalt;
            }

            break;

        } else {

            fm->fieldName = fieldName;
            tm->fieldNameMap[fieldName] = fieldName;
            res = res + fieldName + " text";
            break;

        }

    }
    default: {
        assert_s(false, "unrecognized type in processCreate");
    }
    }

    return res;
}

void
processDecryptionsForOp(string operation, string firstToken,
                        string secondToken,
                        FieldsToDecrypt & fieldsDec, QueryMeta & qm,
                        map<string,
                            TableMetadata *> & tableMetaMap)
throw (CryptDBError)
{

    string firstTable, firstField, secondTable, secondField;

    FieldMetadata * fmfirst = NULL;
    TableMetadata * tmfirst = NULL;
    FieldMetadata * fmsecond = NULL;
    TableMetadata * tmsecond = NULL;

    if (isField(firstToken)) {
        getTableField(firstToken, firstTable, firstField, qm, tableMetaMap);
        tmfirst = tableMetaMap[firstTable];
        fmfirst = tmfirst->fieldMetaMap[firstField];
    }
    if (isField(secondToken)) {
            getTableField(secondToken, secondTable, secondField, qm, tableMetaMap);
            tmsecond = tableMetaMap[secondTable];
            fmsecond = tmsecond->fieldMetaMap[secondField];
    }

    if (fmfirst && fmsecond) {     //JOIN

        assert_s(fmfirst->isEncrypted == fmsecond->isEncrypted,
                 string(
                     "cannot process operation on encrypted and not encrypted field")
                 +
                 fullName(firstField,
                          firstTable) + " " +
                 fullName(secondField, secondTable));

        if (!fmfirst->isEncrypted) {
            //no decryptions to process
            return;
        }

        assert_s(
            fmfirst->INCREMENT_HAPPENED == false &&
            fmsecond->INCREMENT_HAPPENED == false,
            "cannot perform comparison on field that was incremented! (" + firstField + ", " + secondField + ")");

        if (Operation::isDET(operation)) {
            //join by equality

            //if any of the fields are in the semantic state must decrypt
            if (fmfirst->secLevelDET == SECLEVEL::SEMANTIC_DET) {
                addIfNotContained(fullName(firstField,
                                           firstTable), fieldsDec.DETFields);
                addIfNotContained(fullName(firstField,
                                           firstTable),
                                  fieldsDec.DETJoinFields);
            }
            if (fmsecond->secLevelDET == SECLEVEL::SEMANTIC_DET) {
                addIfNotContained(fullName(secondField,
                                           secondTable), fieldsDec.DETFields);
                addIfNotContained(fullName(secondField,
                                           secondTable),
                                  fieldsDec.DETJoinFields);
            }
            if (fmfirst->secLevelDET == SECLEVEL::DET) {
                addIfNotContained(fullName(firstField,
                                           firstTable),
                                  fieldsDec.DETJoinFields);
            }
            if (fmsecond->secLevelDET == SECLEVEL::DET) {
                addIfNotContained(fullName(secondField,
                                           secondTable),
                                  fieldsDec.DETJoinFields);
            }

            return;
        }

        //join by inequality

        assert_s(false, "join not supported for inequality");
        assert_s(Operation::isOPE(operation), "unexpected operation ");

        //must bring both to joinable level
        if (fmfirst->secLevelOPE == SECLEVEL::SEMANTIC_OPE) {
            addIfNotContained(fullName(firstField,
                    firstTable), fieldsDec.OPEFields);
        }
        if (fmsecond->secLevelOPE == SECLEVEL::SEMANTIC_OPE) {
            addIfNotContained(fullName(secondField,
                    secondTable), fieldsDec.OPEFields);
        }
        if (fmfirst->secLevelOPE == SECLEVEL::OPE) {
            addIfNotContained(fullName(firstField,
                    firstTable),
                    fieldsDec.OPEJoinFields);
        }

        if (fmsecond->secLevelOPE == SECLEVEL::OPE) {
            addIfNotContained(fullName(secondField,
                    secondTable),
                    fieldsDec.OPEJoinFields);
        }

        return;

    }

    // It is not join

    if (Operation::isILIKE(operation)) {
        fmfirst->search_used = true;
        return;
    }

    if (Operation::isIN(operation) && (fmfirst)) {
        if (!fmfirst->isEncrypted)
        {
            return;
        }

        if (fmfirst->secLevelDET == SECLEVEL::SEMANTIC_DET) {
            addIfNotContained(fullName(firstField,
                                       firstTable), fieldsDec.DETFields);
            addIfNotContained(fullName(firstField,
                                       firstTable), fieldsDec.DETJoinFields);
        }
        if (fmfirst->secLevelDET == SECLEVEL::DET) {
            addIfNotContained(fullName(firstField,
                                       firstTable), fieldsDec.DETFields);
        }
        return;
    }

    //we have a filter -- one of the elements is a constant

    //figure out which is the field
    FieldMetadata * fmField;
    string tableField;

    if (fmfirst) {
        fmField = fmfirst;
        tableField = fullName(firstField, firstTable);
    } else {
        assert_s(isField(secondToken), " invalid token ");
        fmField = fmsecond;
        tableField = fullName(secondField, secondTable);
    }

    if (!fmField->isEncrypted) {
        //no decryptions to process
        return;
    }

    if (Operation::isDET(operation)) {

        assert_s(fmField->INCREMENT_HAPPENED == false,
                 "cannot perform comparison on field that was incremented: " + firstField);
        //filter with equality
        if (fmField->secLevelDET == SECLEVEL::SEMANTIC_DET) {
            addIfNotContained(tableField, fieldsDec.DETFields);
        }

        return;
    }

    //filter with inequality

    fmField->ope_used = true;

    if (fmField->secLevelOPE == SECLEVEL::SEMANTIC_OPE) {
        addIfNotContained(tableField, fieldsDec.OPEFields);
    }

}

string
getTableSalt(string anonTableName) {
    return BASE_SALT_NAME + "_t_" + anonTableName;
}
string
getFieldSalt(unsigned int index, string anonTableName) {
    return BASE_SALT_NAME + "_f_" + StringFromVal(index)+"_"+anonTableName;
}


bool
isSalt(string id, bool & isTableSalt)
{
    if (id.find(BASE_SALT_NAME) == 0 || (isTableField(id) && (getField(id).find(BASE_SALT_NAME) == 0))) {
        if (id.find(BASE_SALT_NAME+"_t_") == 0) {
            isTableSalt = true;
        } else {
            isTableSalt = false;
        }
        return true;
    }

    return false;
}

string
getTableOfSalt(string salt_name) {

    return salt_name.substr(BASE_SALT_NAME.length() + 3, salt_name.length() - 3 - BASE_SALT_NAME.length());
}

bool
isNested(const string &query)
{
    list<string> queryS = getSQLWords(query);

    for (list<string>::iterator it = queryS.begin(); it != queryS.end();
         it++) {
        if (equalsIgnoreCase(*it, "in")) {
            if (equalsIgnoreCase (*it, "(")) {
                it++;
            }
            if (isCommand(*it)) {
                assert_s(false, "nested query\n");
                return true;
            }
        }
    }

    return false;
}

bool
isCommand(string str)
{
    return contains(str, commands);
}

string
getOnionName(FieldMetadata * fm, onion o)
{
    if (fm->isEncrypted) {
        switch (o) {
        case oDET: {return fm->anonFieldNameDET; }
        case oOPE: {return fm->anonFieldNameOPE; }
        case oAGG: {return fm->anonFieldNameAGG; }
        case oNONE: {return ""; }
        default: {assert_s(false, "unexpected onion type \n"); }
        }
    } else {
        return fm->fieldName;
    }

    assert_s(false, "unexpected onion type \n");
    return "";
}

SECLEVEL
getLevelForOnion(FieldMetadata * fm, onion o)
{
    switch (o) {
    case oAGG: {return SECLEVEL::SEMANTIC_AGG; }
    case oDET: { return fm->secLevelDET; }
    case oOPE: { return fm->secLevelOPE; }
    case oNONE: {return SECLEVEL::PLAIN; }
    default: {assert_s(false, "invalid onion type in getLevelForOnion"); }
    }

    return SECLEVEL::INVALID;
}
SECLEVEL
getLevelPlain(onion o)
{
    switch (o) {
    case oAGG: {return SECLEVEL::PLAIN_AGG; }
    case oDET: { return SECLEVEL::PLAIN_DET; }
    case oOPE: { return SECLEVEL::PLAIN_OPE; }
    case oNONE: {return SECLEVEL::PLAIN; }
    default: {assert_s(false, "invalid onion type in getLevelForOnion"); }
    }

    return SECLEVEL::INVALID;
}

bool
isTable(string token, const map<string, TableMetadata *> & tm)
{
    return tm.find(token) != tm.end();
}

// > 0 : sensitive field
// < 0 : insensitive field
// = 0 : other: constant, operation, etc.
static int
isSensitive(string tok, QueryMeta & qm, map<string, TableMetadata *> & tm,
            string & fieldname)
{

    fieldname = tok;

    if (!isField(tok)) {
        return 0;
    }

    string table, field;
    getTableField(tok, table, field, qm, tm);

    FieldMetadata * fm = tm[table]->fieldMetaMap[field];

    if (fm->isEncrypted) {
        if (isTableField(tok)) {

        }
        return 1;
    } else {
        if (tm[table]->hasEncrypted) {
            fieldname =
                fieldNameForQuery(tm[table]->anonTableName, table, field,
                                  fm,
                                  qm);
        }
        return -1;
    }

}

bool
processSensitive(list<string>::iterator & it, list<string> & words,
                 string & res, QueryMeta & qm,
                 map<string,
                     TableMetadata *> & tm)
{
    vector<string> keys = {"AND", "OR", "NOT"};

    bool foundSensitive = false;
    bool foundInsensitive = false;

    list<string>::iterator newit = it;


    int openParen = 0;

    while ((newit != words.end()) && (!contains(*newit, keys))
           && (!isQuerySeparator(*newit))  &&
           (!((openParen == 0) && (newit->compare(")") == 0))) ) {

        if (newit->compare("(") == 0) {
            openParen++;
        }
        if (newit->compare(")") == 0) {
            openParen--;
        }
        string newtok;
        int iss = isSensitive(*newit, qm, tm, newtok);

        res += " " + newtok;

        if (iss > 0) {
            foundSensitive = true;
        }
        if (iss < 0) {
            foundInsensitive = true;
        }
        newit++;
    }

    assert_s(
        !(foundSensitive && foundInsensitive),
        "cannot have operation with both sensitive and insensitive columns");
    if (foundSensitive) {
        return true;
    }

    it = newit;
    return false;

}
string
getFieldsItSelect(list<string> & words, list<string>::iterator & it)
{
    it = words.begin();
    it++;
    string res = "SELECT ";

    if (equalsIgnoreCase(*it, "distinct")) {
        LOG(edb_v) << "has distinct!";
        it++;
        res += "DISTINCT ";
    }

    return res;
}

QueryMeta
getQueryMeta(command c, list<string> query, map<string, TableMetadata *> & tm)
throw (CryptDBError)
{
    LOG(edb_v) << "in getquery meta";

    std::set<string> delims;

    switch(c) {
    case cmd::SELECT:
        delims = { "from", "left" };
        break;

    case cmd::DELETE:
        delims = { "from", "left" };
        break;

    case cmd::INSERT:
        delims = { "into" };
        break;

    case cmd::UPDATE:
        delims = { "update" };
        break;

    default:
        assert_s(false, "given unexpected command in getQueryMeta");
    }

    auto qit = query.begin();

    QueryMeta qm = QueryMeta();

    mirrorUntilTerm(qit, query, delims, 0);

    assert_s(qit != query.end(), "query does not have delims in getQueryMeta");

    while (qit!=query.end() && (contains(*qit, delims))) {
        if (equalsIgnoreCase(*qit, "left")) {
            roll<string>(qit, 2);
        } else {
            qit++;
        }
        while ((qit != query.end()) && (!isQuerySeparator(*qit))) {
            if (qit->compare("(")==0) {
                qit++;
            }
            string tableName = *qit;
            //comment for speed
            assert_s(tm.find(tableName) != tm.end(), string("table ") + tableName
             + " is invalid");
            qm.tables.push_back(tableName);
            qit++;
            string alias = getAlias(qit, query);
            if (alias.length() > 0) {
                qm.tabToAlias[tableName] = alias;
                qm.aliasToTab[alias] = tableName;
            }
            processAlias(qit, query);
        }
        mirrorUntilTerm(qit, query, delims, 0);
        if (qit != query.end())
            LOG(edb_v) << "after mirror, qit is " << *qit;
    }

    if (c == cmd::SELECT) {

        //we are now building field aliases
        list<string>::iterator it;
        getFieldsItSelect(query, it);
        while (!isQuerySeparator(*it)) {
            string term = *it;
            it++;             //go over field
            //mirror any matching parenthesis
            term += processParen(it, query);
            string alias = getAlias(it, query);
            if (alias.length() > 0) {
                qm.aliasToField[alias] = term;
            }
            processAlias(it, query);
        }

    }

    return qm;

}

string
processAgg(list<string>::iterator & wordsIt, list<string> & words,
           string & field, string & table, onion & o, QueryMeta & qm,
           map<string, TableMetadata *> & tm,
           bool forquery)
{
    if (wordsIt == words.end()) {
        LOG(edb_v) << "process agg gets empty token list";
        return "";
    }
    if (!isAgg(*wordsIt)) {
        return "";
    }

    LOG(edb_v) << "is agg";
    string agg = *wordsIt;

    string res = "";
    int noParen = 0;

    while (isKeyword(*wordsIt) && (wordsIt->compare("*"))) {
        res = res + *wordsIt;
        wordsIt++;
        if (wordsIt->compare("(") == 0) {
            noParen++;
            res = res + "(";
            wordsIt++;
        } else {
            res = res + " ";
        }
    }

    if (wordsIt->compare("*") == 0) {
        res += "*";
        table = "";
        field = "";
        o = oNONE;
        goto closingparen;
    }

    LOG(edb_v) << "in agg, field is " << *wordsIt;
    getTableField(*wordsIt, table, field, qm, tm);

    LOG(edb_v) << "before if table: " << table << " field " << field;

    if (tm[table]->fieldMetaMap[field]->isEncrypted) {
        if (equalsIgnoreCase(agg, "min")) {o = oOPE; }
        if (equalsIgnoreCase(agg, "max")) {o = oOPE; }
        if (equalsIgnoreCase(agg, "count")) {o = oNONE; }
        if (equalsIgnoreCase(agg, "sum")) {o = oAGG; }
    } else {
        o = oNONE;
    }

    if (forquery) {
        TableMetadata * tmet = tm[table];
        FieldMetadata * fm = tmet->fieldMetaMap[field];
        if (fm->isEncrypted) {
            res = res +
                  fieldNameForQuery(tmet->anonTableName, table,
                                    getOnionName(fm,
                                                 o),
                                    fm, qm);
        } else {
            res = res + *wordsIt;
        }
    } else {
        res = res + fieldNameForResponse(table, field, *wordsIt, qm, true);
    }

closingparen:

    wordsIt++;

    //there may be other stuff before first parent
    res += mirrorUntilTerm(wordsIt, words, {")"}, 0, 0);

    for (int i = 0; i < noParen; i++) {
        assert_s(wordsIt->compare(")") == 0, "expected ) but got " + *wordsIt);
        res = res + ")";
        wordsIt++;
    }

    string alias = getAlias(wordsIt, words);
    string palias = processAlias(wordsIt, words);

    if (forquery) {
        res += palias;
        return res;
    } else {
        if (alias.length() > 0) {
            return alias;
        } else {
            return res;
        }
    }

}

bool
isField(string token)
{

    if (isKeyword(token)) {
        return false;
    }
    if (token.find("(") != string::npos) {
        return false;
    }
    if (token.find(")") != string::npos) {
        return false;
    }

    if (!isalpha(token[0])) {
        return false;
    }

    bool hasPeriod = false;
    //must contain only letters
    for (unsigned int i = 1; i < token.length(); i++) {
        if (token[i] == '.') {
            if (hasPeriod) {
                //if it has more than one period is bad
                return false;
            }
            hasPeriod = true;
        } else {
            if ((!(isalnum(token[i])) && (token[i] != '_'))) {
                return false;
            }
        }
    }
    return true;
}

string
getField(string tablefield)
{
    if (isTableField(tablefield)) {
        size_t pos = tablefield.find(".");
        return tablefield.substr(pos+1, tablefield.length() - pos - 1);
    } else {
        return tablefield;
    }
}

string
getTable(string tablefield)
{
    if (isTableField(tablefield)) {
        size_t pos = tablefield.find(".");
        return tablefield.substr(0, pos);
    } else {
        return "";
    }
}

void
getTableField(string token, string & table, string & field, QueryMeta & qm,
              map<string,
                  TableMetadata * > & tableMetaMap)
throw (CryptDBError)
{

    assert_s(isField(
                 token), "token given to getTableField is not a field " +
             token);

    // token has form: table.field
    if (isTableField(token)) {
        size_t position = token.find('.');
        myassert(position != string::npos,
                 "a field must be of the form table.field");
        table = token.substr(0, position);
        field = token.substr(position+1, token.length() - position - 1);
        if (tableMetaMap.find(table) == tableMetaMap.end()) {
            //Comment out for SPEED
            assert_s(qm.aliasToTab.find(table) != qm.aliasToTab.end(),
             "table name " + table + "does not exist and is not alias");
            table = qm.aliasToTab[table];
        }
        TableMetadata * tm = tableMetaMap[table];

        if (field.compare("*") != 0) {
            //Comment out for SPEED
             assert_s(tm->fieldMetaMap.find(field) != tm->fieldMetaMap.end(),
             "field does not exist inside given table");
        }
        return;
    }

    //token is *
    if (token.compare("*") == 0) {
        table = "";
        field = "*";
        return;
    }

    //token has form: field

    for (list<string>::iterator it = qm.tables.begin(); it!=qm.tables.end();
         it++) {
        TableMetadata * tm = tableMetaMap[*it];
        if (tm->fieldMetaMap.find(token) != tm->fieldMetaMap.end()) {
            table = *it;
            field = token;
            return;
        }
    }

    //token is an alias of a field
    if (qm.aliasToField.find(token) != qm.aliasToField.end()) {
        table = "";
        field = token;
        return;
    }

    assert_s(false,
             "the given field <" + token + "> is not present in any table");

}

string
fieldNameForQuery(string anontable, string table,  string anonfield,
                  const FieldMetadata * fm, QueryMeta & qm,
                  bool ignoreDecFirst)
{

    string res = "";

    //it is using the name of the table alias
    if (qm.tabToAlias.find(table) != qm.tabToAlias.end()) {
        res = qm.tabToAlias[table];
    } else {
        res = anontable;
    }

    res = res + ".";

    if (fm->isEncrypted) {
        res = res +anonfield;
    } else {
        res = res + fm->fieldName;
    }


    if (DECRYPTFIRST && (!ignoreDecFirst)) {
        if (fm->type == TYPE_INTEGER) {
            //replace name of field with UDF having key
            res = " decrypt_int_det(" + res + "," +
                  CryptoManager::marshallKey(dec_first_key) + ") ";

        } else {
            //text
            res  = " decrypt_text_sem(" + res + "," +
                   CryptoManager::marshallKey(dec_first_key) + ", 0 ) ";
        }
    }

    return res;
}

string
fieldNameForResponse(string table, string field, string origName,
                     QueryMeta & qm, bool isAgg)
{
    if (origName.compare("*") == 0) {
        return origName;
    }

    if (!isAgg) {
        return field;
    }
    if (!isTableField(origName)) {
        //no table included
        return field;
    } else {
        //need to include table name
        if (qm.tabToAlias.find(table) != qm.tabToAlias.end()) {
            return qm.tabToAlias[table] + "." + field;
        } else {
            return table + "." + field;
        }
    }

}

void
QueryMeta::cleanup()
{
    aliasToField.clear();
    aliasToTab.clear();
    tabToAlias.clear();
    tables.clear();
}
