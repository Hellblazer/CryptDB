#include <algorithm>
#include <string>
#include <iomanip>
#include <stdexcept>
#include <assert.h>

#include <openssl/rand.h>

#include <util/util.hh>
#include <util/cryptdb_log.hh>


using namespace std;
using namespace NTL;

void
myassert(bool value, const string &mess)
{
    if (ASSERTS_ON) {
        if (!value) {
            LOG(warn) << "ERROR: " << mess;
            throw std::runtime_error(mess);
        }
    }
}

void
assert_s (bool value, const string &msg)
throw (CryptDBError)
{
    if (ASSERTS_ON) {
        if (!value) {
            LOG(warn) << "ERROR: " << msg;
            throw CryptDBError(msg);
        }
    }
}

ParserMeta::ParserMeta() : clauseKeywords_p(), querySeparators_p()
{

    const unsigned int noKeywords = 33;
    const string clauseKeywords[] =
    {"select", "from",  "where",  "order", "group",  "update", "set", "for",
     "insert",
     "into", "and",  "or",  "distinct",
     "in", "*", "max", "min", "count", "sum", "by", "asc",
     "desc", "limit",
     "null",
     "ilike", "like",
     "integer", "bigint", "text",
     "left", "join", "on", "is"};

    const unsigned int noSeparators = 14;
    const string querySeparators[] = {"from", "where", "left", "on", "group",
                                      "order", "limit", "for", "values", ";", "set",
                                      "group",  "asc", "desc"};

    for (unsigned int i = 0; i < noKeywords; i++)
        clauseKeywords_p.insert(clauseKeywords[i]);
    for (unsigned int i = 0; i < noSeparators; i++)
        querySeparators_p.insert(querySeparators[i]);
}

FieldMetadata::FieldMetadata()
{
    isEncrypted = false;

    can_be_null = true;


    type = TYPE_TEXT;


    //by default, all onions are at maximum security
    secLevelDET = SECLEVEL::SEMANTIC_DET;
    secLevelOPE = SECLEVEL::SEMANTIC_OPE;


    INCREMENT_HAPPENED = false;

    //onions used by default
    has_ope = true;
    has_agg = true;
    has_search = true;
    has_salt = true;

    salt_name = "";

    //none of the onions used yet
    ope_used = false;
    agg_used = false;
    search_used = false;
    update_set_performed = false;
}

TableMetadata::TableMetadata() {
    anonTableName = "";
    tableNo = 0;
    hasEncrypted = false;
    hasSensitive = false;
}

TableMetadata::~TableMetadata()
{
    for (auto i = fieldMetaMap.begin(); i != fieldMetaMap.end(); i++)
        delete i->second;
    for (auto i = indexes.begin(); i != indexes.end(); i++)
        delete *i;
}

double
timeInSec(struct timeval tvstart, struct timeval tvend)
{
    return
        ((double) (tvend.tv_sec - tvstart.tv_sec) +
         ((double) (tvend.tv_usec - tvstart.tv_usec)) / 1000000.0);
}

string
randomBytes(unsigned int len)
{
    string s;
    s.resize(len);
    RAND_bytes((uint8_t*) &s[0], len);
    return s;
}

uint64_t
randomValue()
{
    return IntFromBytes((const uint8_t*) randomBytes(8).c_str(), 8);
}

string
stringToByteInts(const string &s)
{
    stringstream ss;
    bool first = true;
    for (size_t i = 0; i < s.length(); i++) {
        if (!first)
            ss << " ";
        ss << (uint) (uint8_t) s[i];
        first = false;
    }
    return ss.str();
}

string
angleBrackets(const string &s)
{
    return "<" + s + ">";
}

string
checkStr(list<string>::iterator & it, list<string> & words, const string &s1,
         const string &s2)
{

    if (it == words.end()) {
        return "";
    }
    if (it->compare(s1) == 0) {
        it++;
        return s1;
    }
    if (it->compare(s2) == 0) {
        return "";
    }
    if (isQuerySeparator(*it)) {
        return "";
    }

    assert_s(false, string("expected ") + s1 + " or " + s2 + " given " + *it );
    return "";
}

string
BytesFromInt(uint64_t value, unsigned int noBytes)
{
    string result;
    result.resize(noBytes);

    for (uint i = 0; i < noBytes; i++) {
        result[noBytes-i-1] = ((unsigned char) value) % 256;
        value = value / 256;
    }

    return result;
}

uint64_t
IntFromBytes(const unsigned char * bytes, unsigned int noBytes)
{
    uint64_t value = 0;

    for (unsigned int i = 0; i < noBytes; i++) {
        unsigned int bval = (unsigned int)bytes[i];
        value = value * 256 + bval;
    }

    return value;
}

string
StringFromZZ(const ZZ &x)
{
    string s;
    s.resize(NumBytes(x), 0);
    BytesFromZZ((uint8_t*) &s[0], x, s.length());
    return s;
}

ZZ
ZZFromString(const string &s)
{
    return ZZFromBytes((const uint8_t *) s.data(), s.length());
}



ZZ
UInt64_tToZZ (uint64_t value)
{
    unsigned int unit = 256;
    ZZ power;
    power = 1;
    ZZ res;
    res = 0;

    while (value > 0) {
        res = res + ((long int)value % unit) * power;
        power = power * unit;
        value = value / unit;
    }
    return res;

};

//returns a string representing a value pointed to by it and advances it
//skips apostrophes if there are nay
string
getVal(list<string>::iterator & it)
{
    string res;

    if (hasApostrophe(*it)) {
        res = removeApostrophe(*it);
    } else {
        res = *it;
    }
    it++;

    return res;

}

string
strFromVal(uint64_t x)
{
    stringstream ss;
    ss <<  x;
    return ss.str();
}

string
strFromVal(uint32_t x)
{
    stringstream ss;
    ss << (int32_t) x;
    return ss.str();
}

string
StringFromVal(uint64_t value, uint padLen)
{
    stringstream ss;
    ss << setfill('0') << setw(padLen) << value;
    return ss.str();
}

uint64_t
valFromStr(const string &str)
{
    stringstream ss(str);
    uint64_t val;
    ss >> val;
    return  val;
}

#if MYSQL_S

string
marshallBinary(const string &s)
{
    string r;
    r += "X\'";

    const char *sp = &s[0];
    static const char *digits = "0123456789ABCDEF";
    size_t l = s.length();
    for (size_t i = 0; i < l; i++) {
        r += digits[sp[i] >> 4 & 0xf];
        r += digits[sp[i] & 0xf];
    }

    r += "\'";
    return r;
}

void
printRes(const ResType & r) {

    if (!cryptdb_logger::enabled(log_group::log_edb_v))
        return;

    stringstream ssn;
    for (unsigned int i = 0; i < r.names.size(); i++) {
        char buf[400];
        snprintf(buf, sizeof(buf), "%-20s", r.names[i].c_str());
        ssn << buf;
    }
    LOG(edb_v) << ssn.str();

    /* next, print out the rows */
    for (unsigned int i = 0; i < r.rows.size(); i++) {
        stringstream ss;
        for (unsigned int j = 0; j < r.rows[i].size(); j++) {
            char buf[400];
            snprintf(buf, sizeof(buf), "%-20s", r.rows[i][j].to_string().c_str());
            ss << buf;
        }
        LOG(edb_v) << ss.str();
    }
}


/*
string
marshallSalt(const string &s) {
    assert_s(s.length() == SALT_LEN_BYTES, "salt for marshall does not have right len");

    return strFromVal(IntFromBytes((const unsigned  char *)s.data(), s.length()));
}

string
unmarshallSalt(const string & s) {
    uint64_t val = valFromStr(s);

    return string(BytesFromInt(val, SALT_LEN_BYTES), SALT_LEN_BYTES);

}

*/

#else

string
marshallBinary(unsigned char * v, unsigned int len)
{

    cerr << "\n \n WRONG BINARY \n \n";
    cout << "\n \n WRONG BINARY \n \n"; fflush(stdout);

    string res = "E'";
    cerr << "calling wrong marshall \n";
    for (unsigned int i = 0; i < len; i++) {
        int c = (int) v[i];
        if (c == 39) {
            res = res + "\\\\" + "047";             //StringFromInt((int)v[i],
                                                    // 3)
            continue;
        }
        if (c == 92) {
            res = res + "\\\\" + "134";
            continue;
        }
        if ((c >=0 && c <= 31) || (c >= 127 && c<=255)) {
            res = res + "\\\\" + octalRepr(c);
            continue;
        }
        res = res + (char)v[i];
    }
    res = res + "'";
    return res;
}

#endif

static unsigned char
getFromHex(const string &hexValues)
{
    unsigned int v;
    sscanf(hexValues.c_str(), "%2x", &v);
    return (unsigned char) v;
}

string
unmarshallBinary(const string &s)
{
    uint offset;
    size_t len = s.length();

#if MYSQL_S
    offset = 2;
    myassert(s[0] == 'X',
             "unmarshallBinary: first char is not x; it is " + s[0]);
    len = len - 1;     // removing last apostrophe
#else
    myassert(s[0] == '\\',
             "unmarshallBinary: first char is not slash; it is " + s[0]);
    myassert(s[1] == 'x',
             "unmarshallBinary: second char is not x; it is " + s[1]);
    offset = 2;
#endif

    myassert((len - offset) % 2 == 0,
             "unmarshallBinary: newlen is odd! newlen is " +
             strFromVal(len-offset));

    string r;
    for (uint i = 0; i < (len-offset)/2; i++)
        r += getFromHex(&s[offset+i*2]);
    return r;
}

static bool
matches(const char * query,
        const std::set<char> &delims,
        bool ignoreOnEscape = false,
        int index = 0)
{
    bool res = (delims.find(query[0]) != delims.end());

    if (res && (index > 0)) {
        char c = *(query-1);
        if (c =='\\') {
            return false;
        }
    }

    return res;
}

list<string>
parse(const string &query,
      const std::set<char> &delimsStayArg,
      const std::set<char> &delimsGoArg,
      const std::set<char> &keepIntactArg)
{
    list<string> res;
    size_t len = query.length();

    unsigned int index = 0;

    string word = "";

    while (index < len) {
        while ((index < len) &&
               matches(&query[index], delimsGoArg)) {
            index = index + 1;
        }

        while ((index < len) &&
               matches(&query[index], delimsStayArg)) {
            string sep = "";
            sep = sep + query[index];
            res.push_back(sep);
            index = index + 1;
        }

        if (index >= len) {break; }

        if (matches(&query[index], keepIntactArg, true, index)) {

            word = query[index];

            index++;

            while (index < len)  {

                if (matches(&query[index], keepIntactArg, true,
                            index)) {
                    break;
                }

                word += query[index];
                index++;
            }

            /*
             * check whether keepIntact was closed at index
             */
            assert((index < len)  &&
                   matches(&query[index], keepIntactArg, index));

            word += query[index];
            res.push_back(word);

            index++;

        }

        if (index >= len) {break; }

        word = "";
        while ((index < len) &&
               (!matches(&query[index], delimsStayArg)) &&
               (!matches(&query[index], delimsGoArg)) &&
               (!matches(&query[index], keepIntactArg))) {
            word += query[index];
            index++;
        }

        if (word.length() > 0) {res.push_back(word); }
    }

    return res;

}

static void
consolidateComparisons(list<string> & words)
{
    list<string>::iterator it = words.begin();
    list<string>::iterator oldit;

    while (it!=words.end()) {
        //consolidates comparisons
        if (contains(*it, comparisons)) {
            string res = "";
            //consolidates comparisons
            while ((it != words.end()) &&
                   (contains(*it, comparisons))) {
                res += *it;
                oldit = it;
                it++;
                words.erase(oldit);
            }
            words.insert(it, res);
            it++;
            continue;
        }

        /*
                //consolidates negative numbers
                if (it->compare("-") == 0) {
                        it++;
                        if (isNumber(*it)) {
                                string res = "-" + *it;
                                it--;
                                list<string>::iterator newit = it;
                                newit--;
                                words.insert(res, *it);
                                words.erase(*it);
                                it = ++newit;
                                newit--;
                                words.erase(it);
                                newit++;
                                it = newit;
                        }
                        continue;
                }
         */
        it++;
    }

}

/*void evaluateMath(list<string> & words, list<string>::iterator start,
   list<string>::iterator end) {
   list<string>::iterator it = start;
   string res;
   //reduce the equations chosen
   while ((it != words.end()) && it != end) {
    assert_s(isOnly(*it, math, noMath), "input to evaluateMath is not math");
    res += *it;
    oldit = it;
    it++;
    words.erase(oldit);
   }
   Equation eq;
   eq.set(res);
   res = eq.rpn();
   if (res.compare("") != 0) {
    words.insert(it, res);
   }
   }

   void consolidateMathSelect(list<string> & words) {

   }

   void consolidateMathInsert(list<string> & words) {

   }

   void consolidateMathUpdate(list<string> & words) {

   }*/

static void __attribute__((unused))
consolidateMath(list<string> & words)
{
    command com = getCommand(*words.begin());
    switch (com) {
    case cmd::CREATE:
        cerr << "consolidateMath doesn't deal with CREATE" << endl;
        return;
    case cmd::UPDATE:
        //consolidateMathUpdate(words);
        return;
    case cmd::SELECT:
        //consolidateMathSelect(words);
        return;
    case cmd::INSERT:
        //consolidateMathInsert(words);
        return;
    case cmd::DROP:
        cerr << "consolidateMath doesn't deal with DROP" << endl;
        return;
    case cmd::DELETE:
        cerr << "consolidateMath doesn't deal with DELETE" << endl;
        return;
    case cmd::BEGIN:
        cerr << "consolidateMath doesn't deal with BEGIN" << endl;
        return;
    case cmd::COMMIT:
        cerr << "consolidateMath doesn't deal with COMMIT" << endl;
        return;
    case cmd::ALTER:
        cerr << "consolidateMath doesn't deal with ALTER" << endl;
        return;
    default:
    case cmd::OTHER:
        cerr << "consolidateMath doesn't deal with OTHER (what is this?)" <<
        endl;
        return;
    }
}

/*
        list<string>::iterator it = words.begin();
        list<string>::iterator oldit = it;

        // This will only perform mathematical operations on equations where
           there are no variables in the words of the equations
        //   That is, it will simplify {"x=", "2+3"}, but not {"x=2","+3"}
        while (it != words.end()) {
          //getCommand(first word)
          list<string> select;
          select.push_back("select");
          list<string> insertinto;
          insertinto.push_back("insert");
          list<string> update;
          update.push_back("update");
          list<string> values;
          values.push_back("values");
          list<string> set;
          set.push_back("set");
          list<string> comma;
          set.push_back(",");
          set.push_back(")");
          //for statements of the form SELECT ... WHERE ... = math
          //use processWhere because UPDATE and DELETE are the same --- need
             to process things after WHERE
          //Raluca will email function that sends it afer WHERE
          if (it != words.end() && contains(*it, select)) {
            it++;
            cerr << "select" << endl;
            while (it != words.end() && !contains(*it, commands, noCommands))
               {


            }
          }
          //for statements of the form INSERT INTO ... VALUES (math or text,
             math or text, ...)
          //getExpressions(math or text)
          if (it != words.end() && contains(*it, insertinto)) {
            it++;
            cerr << "insert" << endl;
            while (it != words.end() && !contains(*it, commands, noCommands))
               {
              if (it != words.end() && contains(*it, values)) {
                        it++;
                        assert_s(it->compare("(") == 0, "VALUES is not
                           followed by (");
                        it++;
                        string res = "";
                        //consolidates comma-separated links
                        while ((it != words.end()) && !isKeyword(*it)) {
                          while ((it != words.end()) && !contains(*it, comma))
                             {
                            cerr << *it << endl;
                                if (isOnly(*it, math, noMath)) {
                                        res += *it;
                                        oldit = it;
                                        it++;

                                        words.erase(oldit);
                                } else {
                                        break;
                                }
                          }
                          Equation eq;
                          eq.set(res);
                          res = eq.rpn();
                          if (res.compare("") != 0) {
                            words.insert(it, res);
                          }
                          if (it != words.end()) {
                            it++;
                          }
                        }
                        if (it != words.end()) {
                                it++;
                        }
                        continue;
              }
              it++;
            }
          }
          //for statements of the form UPDATE ... SET ... = math
          //WHERE clause as with SELECT
          //SET ignore for now; maybe do this later
          if (it != words.end() && contains(*it, update)) {
            cerr << "update" << endl;
          }
          //if (it != words.end()) {
          //  it++;
          //}

        }

        }*/

void
consolidate(list<string> & words)
{
    consolidateComparisons(words);
}

//query to parse
//delimsStay, delimsGo, keepIntact for parsing
//tables
//returns sql tokens and places in tables the tables to which this query
// refers
// if tables have aliases, each alias is replaced with the real name
list<string>
getSQLWords(const string &query)
{
    list<string> words = parse(query, delimsStay, delimsGo, keepIntact);

    consolidate(words);

    return words;
}

string
getQuery(ifstream & qFile)
{

    string query = "";
    string line = "";

    while ((!qFile.eof()) && (line.find(';') == string::npos)) {
        getline(qFile, line);
        query = query + line;
    }


    return query;

}



command
getCommand(const string &query)
throw (CryptDBError)
{
    static struct { const char *s; command c; } s2c[] =
    { { "select", cmd::SELECT },
      { "insert", cmd::INSERT },
      { "update", cmd::UPDATE },
      { "delete", cmd::DELETE },
      { "commit", cmd::COMMIT },
      { "begin",  cmd::BEGIN  },
      { "create", cmd::CREATE },
      { "drop",   cmd::DROP   },
      { "alter",  cmd::ALTER  },
      { "train",  cmd::TRAIN  },
      { 0,        cmd::OTHER  } };

    string cmds = query.substr(0, query.find_first_of(" ,;()"));
    transform(cmds.begin(), cmds.end(), cmds.begin(), ::tolower);
    for (uint i = 0; s2c[i].s != 0; i++)
        if (cmds == s2c[i].s)
            return s2c[i].c;
    return cmd::OTHER;
}

string
getAlias(list<string>::iterator & it, list<string> & words)
{

    if (it == words.end()) {
        return "";
    }

    if (equalsIgnoreCase(*it, "as" )) {
        it++;
        return *it;
    }

    if ((it->compare(",") == 0) || (isQuerySeparator(*it))) {
        return "";
    }

    return *it;
}

string
processAlias(list<string>::iterator & it, list<string> & words)
{
    string res = "";
    const vector<string> terms = {",",")"};

    if (it == words.end()) {
        return res;
    }
    if (equalsIgnoreCase(*it, "as")) {
        res = res + " as ";
        it++;
        assert_s(it != words.end(), "there should be field after as");
        res = res + *it + " ";
        it++;

        if (it == words.end()) {
            return res;
        }

        if (contains(*it, terms)) {
            while ((it!=words.end()) && contains(*it, terms)) {
                res = res + *it;
                it++;
            }
            return res;
        }
        if (isQuerySeparator(*it)) {
            return res;
        }
        assert_s(false, "incorrect syntax after as expression ");
        return res;
    }
    if (contains(*it, terms)) {
        while ((it!=words.end()) && contains(*it, terms)) {
            res = res + *it;
            it++;
        }
        return res;
    }
    if (isQuerySeparator(*it)) {
        return res;
    }

    //you have an alias without as
    res = res + " " + *it + " ";
    it++;

    if (it == words.end()) {
        return res;
    }
    if (contains(*it, terms)) {
        while ((it!=words.end()) && contains(*it, terms)) {
            res = res + *it;
            it++;
        }
        return res;
    }
    if (isQuerySeparator(*it)) {
        return res;
    }

    assert_s(false, "syntax error around alias or comma");

    return res;

}

string
processParen(list<string>::iterator & it, const list<string> & words)
{
    if (!it->compare("(") == 0) {
        return "";
    }
    // field token is "("
    int nesting = 1;
    it++;
    string res = "(";
    while ((nesting > 0) && (it!=words.end())) {
        if (it->compare("(") == 0) {
            nesting++;
        }
        if (it->compare(")") == 0) {
            nesting--;
        }
        res = res + " " + *it;
        it++;
    }
    assert_s(nesting == 0, "tokens ended before parenthesis were matched \n");
    return res + " ";
}

string
mirrorUntilTerm(list<string>::iterator & it, const list<string> & words,
                const std::set<string> & terms, bool stopAfterTerm,
                bool skipParenBlock)
{
    string res = "";
    while ((it!=words.end()) && !contains(*it, terms)) {
        if (skipParenBlock) {
            string paren = processParen(it, words);
            if (paren.length() > 0) {
                res = res + paren;
                continue;
            }
        }

        res = res + *it + " ";
        it++;
    }

    if (it!=words.end()) {
        if (stopAfterTerm) {
            res = res + *it + " ";
            it++;
        }
    }

    return res;
}

list<string>::iterator
itAtKeyword(list<string> & lst, const string &keyword)
{
    list<string>::iterator it = lst.begin();
    while (it != lst.end()) {
        if (equalsIgnoreCase(*it, keyword)) {
            return it;
        } else {
            it++;
        }
    }
    return it;
}

string
getBeforeChar(const string &str, char c)
{
    size_t pos = str.find(c);
    if (pos != string::npos) {
        return str.substr(0, pos);
    } else {
        return "";
    }
}

bool
isQuerySeparator(const string &st)
{
    return (parserMeta.querySeparators_p.find(toLowerCase(st)) !=
            parserMeta.querySeparators_p.end());
}

bool
isAgg(const string &value)
{
    return contains(value, aggregates);
}

bool
isOnly(const string &token, const string * values, unsigned int noValues)
{
    for (unsigned int j = 0; j < token.size(); j++) {
        bool is_value = false;
        for (unsigned int i = 0; i < noValues; i++) {
            string test = "";
            test += token[j];
            if (equalsIgnoreCase(test, values[i])) {
                is_value = true;
            }
        }
        if (!is_value) {
            cerr << token[j] << endl;
            return false;
        }
    }
    return true;
}

bool
isKeyword(const string &token)
{
    return (parserMeta.clauseKeywords_p.find(toLowerCase(token)) !=
            parserMeta.clauseKeywords_p.end());
}

static bool
contains(const string &token1, const string &token2, list<pair<string,
                                                               string> > &
         lst)
{
    for (auto it = lst.begin(); it != lst.end(); it++)
        if ((it->first.compare(token1) == 0) &&
            (it->second.compare(token2) == 0))
            return true;

    return false;
}

void
addIfNotContained(const string &token, list<string> & lst)
{
    if (!contains(token, lst)) {
        lst.push_back(token);
    }
}

void
addIfNotContained(const string &token1, const string &token2,
                  list<pair<string,
                            string> >
                  & lst)
{

    if (!contains(token1, token2, lst)) {
        lst.push_back(pair<string, string>(token1, token2));
    }
}

string
removeApostrophe(const string &data)
{
    if (data[0] == '\'') {
        assert_s(data[data.length()-1] == '\'', "not matching ' ' \n");
        return data.substr(1, data.length() - 2);
    } else {
        return data;
    }
}

bool
hasApostrophe(const string &data)
{
    return ((data[0] == '\'') && (data[data.length()-1] == '\''));
}

string
homomorphicAdd(const string &val1, const string &val2, const string &valn2)
{
    ZZ z1 = ZZFromString(val1);
    ZZ z2 = ZZFromString(val2);
    ZZ n2 = ZZFromString(valn2);
    ZZ res = MulMod(z1, z2, n2);
    return StringFromZZ(res);
}

string
toLowerCase(const string &token)
{
    string s = token;
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

bool
equalsIgnoreCase(const string &s1, const string &s2)
{
    return toLowerCase(s1) == toLowerCase(s2);
}

/***************************
 *           Operations
 ****************************/

bool
Operation::isDET(const string &op)
{
    vector<string> dets = {"=", "<>", "in", "!="};
    return contains(op, dets);
}

bool
Operation::isIN(const string &op)
{
    return equalsIgnoreCase(op,"in");
}

bool
Operation::isOPE(const string &op)
{
    vector<string> opes = {"<", ">", "<=", ">="};
    return contains(op, opes);
}

bool
Operation::isILIKE(const string &op)
{
    vector<string> ilikes = {"ilike", "like"};
    return contains(op, ilikes);
}

bool
Operation::isOp(const string &op)
{
    return (isDET(op) || isOPE(op) || isILIKE(op));
}

/*
   bool addAgg(string currentField, string & aggregateFields) {
         currentField = "." + currentField + " ";
     if (aggregateFields.length() == 0) {
         return true;
     }

     if (aggregateFields.find(currentField) != string::npos) {
         return true;
     }

     return false;
   }
 */
