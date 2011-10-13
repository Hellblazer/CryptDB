/*
 * AccessManager.cpp
 *
 *  Created on: April 24, 2011
 *      Authors: cat_red
 */

#include <iomanip>

#include <edb/AccessManager.hh>
#include <util/cryptdb_log.hh>


using namespace std;

#define NODIGITS 4

//------------------------------------------------------------------------------------------
//returns true if e is in ls
static bool
inList(list<string> &ls, string e)
{
    list<string>::iterator it;
    for(it = ls.begin(); it != ls.end(); it++) {
        if(it->compare(e) == 0) {
            return true;
        }
    }
    return false;
}

static bool
inList(list<Prin> &ls, Prin e)
{
    list<Prin>::iterator it;
    for(it = ls.begin(); it != ls.end(); it++) {
        if(*it == e) {
            return true;
        }
    }
    return false;
}

//------------------------------------------------------------------------------------------

MetaAccess::MetaAccess(Connect * c, bool verb)
{
    this->VERBOSE = verb;
    this->public_table = "cryptdb_initalized_principals";
    this->access_table = "cryptdb_access_keys";
    this->conn = c;
}

int
MetaAccess::execute(string sql)
{
    if(!conn->execute(sql)) {
        LOG(am) << "error with sql query " << sql;
        return -1;
    }
    return 0;
}

string
MetaAccess::publicTableName()
{
    return this->public_table;
}

string
MetaAccess::accessTableName()
{
    return this->access_table;
}

string
MetaAccess::sanitize(string unsanitized)
{
    assert_s(unsanitized.find(
                 ".") != string::npos,
             "input sanitize does not have '.' separator");
    size_t nodigits = unsanitized.find(".");

    stringstream ss;
    ss << setfill('0') << setw(NODIGITS) << nodigits;
    string repr = ss.str();

    assert_s(repr.length() <= NODIGITS,
             "given fieldname is longer than max allowed by pruning");

    string result = repr + unsanitized.substr(0, nodigits) +
                    unsanitized.substr(nodigits+1,
                                       unsanitized.length()-1-nodigits);

    return result;
};

string
MetaAccess::unsanitize(string sanitized)
{
    assert_s(sanitized.find(
                 ".") == string::npos,
             "input to unsanitize has '.' separator");
    unsigned int digits = 0;

    for (int i = 0; i < NODIGITS; i++) {
        assert_s(
            int(sanitized[i]-'0') < 10 && int(sanitized[i]-'0') >= 0,
            "the input to unsanitize does not begin with the correct number of digits");
        digits = digits*10 + (int)(sanitized[i]-'0');
    }

    uint64_t fieldlen = sanitized.length() - NODIGITS -digits;

    string res = sanitized.substr(NODIGITS, digits) + "." + sanitized.substr(
        NODIGITS+digits, (unsigned int)fieldlen);

    return res;
};

std::set<string>
MetaAccess::unsanitizeSet(std::set<string> sanitized)
{
    std::set<string> unsanitized;
    std::set<string>::iterator it;
    for(it = sanitized.begin(); it != sanitized.end(); it++) {
        unsanitized.insert(unsanitize(*it));
    }
    return unsanitized;
}

int
MetaAccess::addEqualsCheck(string princ1, string princ2)
{
    string old1 = getGenericPublic(princ1);
    string old2 = getGenericPublic(princ2);
    //only store sets and maps for case 4, where they're necessary -- they may be large
    std::set<string> genToPrin_old1;
    std::set<string> genToPrin_old2;
    map<string, std::set<string> > genHasAccessToList_old;
    map<string, std::set<string> > genAccessibleByList_old;
    std::set<string> givesPsswd_old;
    if (old1 != "" && old2 != "") {
        genToPrin_old1 = genToPrin[old1];
        genToPrin_old2 = genToPrin[old2];
        genHasAccessToList_old = genHasAccessToList;
        genAccessibleByList_old = genAccessibleByList;
        givesPsswd_old = givesPsswd;
    }
    addEquals(princ1, princ2);
    string new1 = getGenericPublic(princ1);
    string new2 = getGenericPublic(princ2);
    assert_s(new1 == new2, "since this is adding an equals, resultant generics should be equal");
    if (!CheckAccess()) {
        //revert addEquals, and return an error
        LOG(am) << "addEqualsCheck failed: the new equals creates an invalid access tree";
        //case 1: neither princ had a generic
        //remove all references to these princs and delete the new generic
        if (old1 == "" && old2 == "") {
            prinToGen.erase(sanitize(princ1));
            prinToGen.erase(sanitize(princ2));
            genToPrin.erase(new1);
            assert_s(CheckAccess(), "addEqualsCheck reverts improperly");
            return -1;
        }

        //case 2: only princ1 had a generic
        //remove all reference to princ2
        if (old1 != "" && old2 == "") {
            prinToGen.erase(sanitize(princ2));
            genToPrin[new1].erase(sanitize(princ2));
            assert_s(CheckAccess(), "addEqualsCheck reverts improperly");
            return -1;
        }

        //case 3: only princ2 had a generic
        //remove all reference to princ1
        if (old1 == "" && old2 != "") {
            prinToGen.erase(sanitize(princ1));
            genToPrin[new1].erase(sanitize(princ1));
            assert_s(CheckAccess(), "addEqualsCheck reverts improperly");
            return -1;
        }
        
        //case 4: both princs had generics
        //reset references to previous
        if (old1 != "" && old2 != "") {
            prinToGen[sanitize(princ1)] = old1;
            prinToGen[sanitize(princ2)] = old2;
            genToPrin[old1] = genToPrin_old1;
            genToPrin[old2] = genToPrin_old2;
            genHasAccessToList = genHasAccessToList_old;
            genAccessibleByList = genAccessibleByList_old;
            givesPsswd = givesPsswd_old;
            assert_s(CheckAccess(), "addEqualsCheck reverts improperly");
            return -1;
        }
    }
    //update database to reflect new generic name (if exists)
    int ret = 0;
    string sql = "UPDATE " + access_table + " SET hasAccessType = '" + new1 + "' WHERE hasAccessType = '" + old1 + "'";
    ret += execute(sql);
    sql = "UPDATE " + access_table + " SET hasAccessType = '" + new2 + "' WHERE hasAccessType = '" + old2 + "'";
    ret += execute(sql);
    sql = "UPDATE " + access_table + " SET accessToType = '" + new1 + "' WHERE accessToType = '" + old1 + "'";
    ret += execute(sql);
    sql = "UPDATE " + access_table + " SET accessToType = '" + new2 + "' WHERE accessToType = '" + old2 + "'";
    ret += execute(sql);
    sql = "UPDATE " + public_table + " SET Type = '" + new1 + "' WHERE Type = '" + old1 + "'";
    ret += execute(sql);
    sql = "UPDATE " + public_table + " SET Type = '" + new2 + "' WHERE Type = '" + old2 + "'";
    ret += execute(sql);
    return ret;
}

void
MetaAccess::addEquals(string princ1, string princ2)
{
    if (VERBOSE) {
        LOG(am_v) << "addEquals(" << princ1 << "," << princ2 << ")\n";
    }
    //remove any illegal characters (generally, just '.')
    princ1 = sanitize(princ1);
    princ2 = sanitize(princ2);

    string gen;
    bool princ1_in_prinToGen = (prinToGen.find(princ1) == prinToGen.end());
    bool princ2_in_prinToGen = (prinToGen.find(princ2) == prinToGen.end());

    //case 1: neither princ has a generic yet, create a new generic for the
    // two of them
    if (princ1_in_prinToGen && princ2_in_prinToGen) {
        gen = createGeneric(princ1);
        prinToGen[princ2] = gen;
        genToPrin[gen].insert(princ2);
        return;
    }

    //case 2: only princ1 has a generic, add princ2 to that generic
    if (!princ1_in_prinToGen && princ2_in_prinToGen) {
        gen = prinToGen[princ1];
        prinToGen[princ2] = gen;
        genToPrin[gen].insert(princ2);
        return;
    }

    //case 3: only princ2 has a generic, add princ1 to that generic
    if (princ1_in_prinToGen && !princ2_in_prinToGen) {
        gen = prinToGen[princ2];
        prinToGen[princ1] = gen;
        genToPrin[gen].insert(princ1);
        return;
    }

    //case 4: both have generics, merge them into princ1's generic
    gen = prinToGen[princ1];
    string gen2 = prinToGen[princ2];
    std::set<string>::iterator it;
    //update givesPsswd
    if (givesPsswd.find(gen2) != givesPsswd.end()) {
        givesPsswd.insert(gen);
        givesPsswd.erase(gen2);
    }
    //update hasAccessTo/Accessible information, and delete gen2 from lists
    if (genHasAccessToList.find(gen2) != genHasAccessToList.end()) {
        std::set<string> gen2HasAccessTo = genHasAccessToList[gen2];
        for(it = gen2HasAccessTo.begin(); it != gen2HasAccessTo.end();
            it++) {
            genHasAccessToList[gen].insert((*it));
            genAccessibleByList[(*it)].insert(gen);
            if (genAccessibleByList[(*it)].find(gen2) !=
                genHasAccessToList[(*it)].end()) {
                genAccessibleByList[(*it)].erase(gen2);
            }
        }
        if (genHasAccessToList.find(gen2) != genHasAccessToList.end()) {
            genHasAccessToList.erase(gen2);
        }
    }
    if (genAccessibleByList.find(gen2) != genAccessibleByList.end()) {
        std::set<string> gen2Accessible = genAccessibleByList[gen2];
        for(it = gen2Accessible.begin(); it != gen2Accessible.end(); it++) {
            genAccessibleByList[gen].insert(*it);
            genHasAccessToList[(*it)].insert(gen);
            if (genHasAccessToList[(*it)].find(gen2) !=
                genHasAccessToList[(*it)].end()) {
                genHasAccessToList[(*it)].erase(gen2);
            }
        }
        if (genAccessibleByList.find(gen2) != genAccessibleByList.end()) {
            genAccessibleByList.erase(gen2);
        }
    }
    //update equals relations
    for(it = genToPrin[gen2].begin(); it != genToPrin[gen2].end(); it++) {
        genToPrin[gen].insert(*it);
    }
    genToPrin.erase(gen2);
    prinToGen[princ2] = gen;
}

int
MetaAccess::addAccessCheck(string princHasAccess, string princAccessible)
{
    string old_hasAccess = getGenericPublic(princHasAccess);
    string old_accessible = getGenericPublic(princAccessible);
    std::set<string> old_genHasAccessToList;
    std::set<string> old_genAccessibleByList;
    if (old_hasAccess != "") {
        old_genAccessibleByList = genAccessibleByList[old_accessible];
    }
    if (old_accessible != "") {
        old_genHasAccessToList = genHasAccessToList[old_hasAccess];
    }
    addAccess(princHasAccess, princAccessible);
    if (!CheckAccess()) {
        //revert addAccess:
        //if old_* = "", then * didn't exist before, and can be erased from the sets and maps
        //if old_* != "", then * might have already been in the set, so revert to saved copies
        if (old_hasAccess != "") {
            genHasAccessToList[old_hasAccess] = old_genHasAccessToList;
        } else {
            genHasAccessToList.erase(old_hasAccess);
            genToPrin.erase(getGeneric(princHasAccess));
            prinToGen.erase(sanitize(princHasAccess));
        }

        if (old_accessible != "") {
            genAccessibleByList[old_accessible] = old_genAccessibleByList;
        } else {
            genAccessibleByList.erase(old_accessible);
            genToPrin.erase(getGeneric(princHasAccess));
            prinToGen.erase(sanitize(princHasAccess));
        }
        assert_s(CheckAccess(), "addAccessCheck reverts improperly");
        return -1;
    }
    //since adding an access tree link doesn't change any of the existing data,
    // the database is unaffected
    return 0;
}

void
MetaAccess::addAccess(string princHasAccess, string princAccessible)
{
    if (VERBOSE) {
        LOG(am_v) << "addAccess(" << princHasAccess << ","  <<
        princAccessible << ")";
    }

    //get the generic principals these princs are part of
    string genHasAccess = getGeneric(princHasAccess);
    string genAccessible = getGeneric(princAccessible);

    std::set<string>::iterator it;

    //add to genHasAccessToList as:  genHasAccess --> [genAccessible]
    if (genHasAccessToList.find(genHasAccess) == genHasAccessToList.end()) {
        std::set<string> genAccessible_set;
        genAccessible_set.insert(genAccessible);
        genHasAccessToList[genHasAccess] = genAccessible_set;
    } else {
        genHasAccessToList[genHasAccess].insert(genAccessible);
    }

    //add to genAcccesibleBy as:  genAccessible --> [genHasAccess]
    if (genAccessibleByList.find(genAccessible) ==
        genAccessibleByList.end()) {
        std::set<string> genHasAccess_set;
        genHasAccess_set.insert(genHasAccess);
        genAccessibleByList[genAccessible] = genHasAccess_set;
    } else {
        genAccessibleByList[genAccessible].insert(genHasAccess);
    }
}

int
MetaAccess::addGivesCheck(string princ)
{
    addGives(princ);
    if (!CheckAccess()) {
        givesPsswd.erase(getGeneric(princ));
        assert_s(CheckAccess(), "addGivesCheck reverts improperly");
        return -1;
    }
    //since gives has no effect on the access tables, no need to do anything else
    return 0;
}
    

void
MetaAccess::addGives(string princ)
{
    if (VERBOSE) {
        LOG(am_v) << "addGives(" << princ << ")";
    }
    //get the generic principal princ is part of
    string gen_gives = getGeneric(princ);
    //add the generic to the set of generics that give passwords
    givesPsswd.insert(gen_gives);
}

std::set<string>
MetaAccess::getTypesAccessibleFrom(string princ)
{
    assert_s(prinToGen.find(sanitize(
                                princ)) != prinToGen.end(), "input " +
             princ +
             " to getAccessibleFrom is not a known principal");
    string gen_accessed = getGeneric(princ);
    std::set<string> accessible_from;
    std::set<string>::iterator it;
    std::set<string>::iterator it2;
    //things accessible from this principal
    if(genAccessibleByList.find(gen_accessed) != genAccessibleByList.end()) {
        for(it = genAccessibleByList[gen_accessed].begin();
            it != genAccessibleByList[gen_accessed].end(); it++) {
            assert_s(genToPrin.find(
                         *it) != genToPrin.end(),
                     "getAccessibleFrom: gen not in genToPrin");
            std::set<string> from_set = genToPrin[(*it)];
            for(it2 = from_set.begin(); it2 != from_set.end(); it2++) {
                accessible_from.insert(*it2);
            }
        }
    }
    //things equal to this principal
    assert_s(genToPrin.find(
                 gen_accessed) != genToPrin.end(),
             "getAccessibleFrom: input not known");

    return unsanitizeSet(accessible_from);
}

std::set<string>
MetaAccess::getGenAccessibleFrom(string gen)
{
    assert_s(genToPrin.find(
                 gen) != genToPrin.end(),
             "input to getGenAccessibleFrom is not a known principal");
    string gen_accessed = gen;
    std::set<string> accessible_from;
    std::set<string>::iterator it;
    //things accessible from this principal
    accessible_from.insert(gen_accessed);
    if(genAccessibleByList.find(gen_accessed) != genAccessibleByList.end()) {
        for(it = genAccessibleByList[gen_accessed].begin();
            it != genAccessibleByList[gen_accessed].end(); it++) {
            accessible_from.insert(*it);
        }
    }

    return accessible_from;
}

std::set<string>
MetaAccess::getTypesHasAccessTo(string princ)
{
    assert_s(prinToGen.find(sanitize(
                                princ)) != prinToGen.end(),
             princ+" input to getHasAccessTo is not a known principal");
    string gen_accessing = getGeneric(princ);
    std::set<string> can_access;
    std::set<string>::iterator it;
    std::set<string>::iterator it2;
    //things accessible from this principal
    if(genHasAccessToList.find(gen_accessing) != genHasAccessToList.end()) {
        for(it = genHasAccessToList[gen_accessing].begin();
            it != genHasAccessToList[gen_accessing].end(); it++) {
            assert_s(genToPrin.find(
                         *it) != genToPrin.end(),
                     "getHasAccessTo: gen not in genToPrin");
            std::set<string> from_set = genToPrin[(*it)];
            for(it2 = from_set.begin(); it2 != from_set.end(); it2++) {
                can_access.insert(*it2);
            }
        }
    }
    //things equal to this principal
    assert_s(genToPrin.find(
                 gen_accessing) != genToPrin.end(),
             "getHasAccessTo: input not known");

    return unsanitizeSet(can_access);
}

std::set<string>
MetaAccess::getGenHasAccessTo(string gen)
{
    assert_s(genToPrin.find(
                 gen) != genToPrin.end(),
             gen+" gen input to getHasAccessTo is not a known principal");
    string gen_accessing = gen;
    std::set<string> can_access;
    std::set<string>::iterator it;
    can_access.insert(gen_accessing);
    //things accessible from this principal
    if(genHasAccessToList.find(gen_accessing) != genHasAccessToList.end()) {
        for(it = genHasAccessToList[gen_accessing].begin();
            it != genHasAccessToList[gen_accessing].end(); it++) {
            can_access.insert(*it);
        }
    }

    return can_access;
}

std::set<string>
MetaAccess::getEquals(string princ)
{
    assert_s(prinToGen.find(sanitize(
                                princ)) != prinToGen.end(),
             "input to getEquals is not a known principal");
    string gen = getGeneric(princ);
    return unsanitizeSet(genToPrin[gen]);
}

bool
MetaAccess::isGives(string princ)
{
    assert_s(prinToGen.find(sanitize(
                                princ)) != prinToGen.end(),
             "input to isGives is not a known principal");
    string gen = getGeneric(princ);
    if (givesPsswd.find(gen) != givesPsswd.end()) {
        return true;
    }
    return false;
}

bool
MetaAccess::isGenGives(string gen)
{
    if (givesPsswd.find(gen) != givesPsswd.end()) {
        return true;
    }
    return false;
}

string
MetaAccess::getGeneric(string princ)
{
    //remove any illegal characters (generally, just '.')
    princ = sanitize(princ);
    //if this principal has no generic, create one with the name gen_princ
    if (prinToGen.find(princ) == prinToGen.end()) {
        createGeneric(princ);
    }

    return prinToGen[princ];
}

string
MetaAccess::getGenericPublic(string princ)
{
    princ = sanitize(princ);
    if (prinToGen.find(princ) == prinToGen.end()) {
        LOG(am_v) << "Could not find generic for " << princ;

        return "";
    }
    return prinToGen[princ];
}

string
MetaAccess::createGeneric(string clean_princ)
{
    string gen = "gen_" + clean_princ;
    prinToGen[clean_princ] = gen;
    std::set<string> princ_set;
    princ_set.insert(clean_princ);
    genToPrin[gen] = princ_set;
    return gen;
}

bool
MetaAccess::CheckAccess()
{
    std::set<string>::iterator gives;
    std::set<string> results;
    LOG(am_v) << "CHECKING ACCESS TREE FOR FALACIES";

    for (gives = givesPsswd.begin(); gives != givesPsswd.end(); gives++) {
        std::set<string> current_layer = getGenHasAccessTo(*gives);
        std::set<string> next_layer;
        std::set<string>::iterator current_node;
        std::set<string>::iterator next_node;

        results.insert(*gives);

        for(current_node = current_layer.begin();
            current_node != current_layer.end(); current_node++) {
            results.insert(*current_node);
        }

        while(current_layer.size() != 0) {
            for(current_node = current_layer.begin();
                current_node != current_layer.end(); current_node++) {
                std::set<string> next = getGenHasAccessTo(*current_node);
                for(next_node = next.begin(); next_node != next.end();
                    next_node++) {
                    if (results.find(*next_node) == results.end()) {
                        results.insert(*next_node);
                        next_layer.insert(*next_node);
                    }
                }
            }
            current_layer = next_layer;
            next_layer.clear();
        }
    }


    if (results.size() != genToPrin.size()) {
        if(VERBOSE) { LOG(am_v) << "wrong number of results"; }
        return false;
    }

    for (gives = results.begin(); gives != results.end(); gives++) {
        if (genToPrin.find(*gives) == genToPrin.end()) {
            if (VERBOSE) { LOG(am_v) << "wrong results"; }
            cerr << "wrong results" << endl;
            return false;
        }
    }

    return true;
}

int
MetaAccess::CreateTables()
{
    LOG(am_v) << "create tables";
    assert_s(
        CheckAccess(),
        "ERROR: there is an access chain that does not terminate at a givesPsswd principal");
    string sql, num;
    map<string, std::set<string> >::iterator it;
    std::set<string>::iterator it_s;
    //Public Keys table
    sql = "DROP TABLE IF EXISTS " + public_table;
    if (execute(sql) < 0) {
        return -1;
    }
    sql = "CREATE TABLE " + public_table + " (Type " +  PRINCTYPE +
          ", Value " PRINCVALUE ", Asym_Public_Key " TN_PK_KEY
          ", Asym_Secret_Key " TN_PK_KEY
          ", Salt " + TN_SALT + ", PRIMARY KEY (Type,Value))";
    if (execute(sql) < 0) {
        return -1;
    }
    //Access Keys table
    sql = "DROP TABLE IF EXISTS " + access_table;
    if (execute(sql) < 0) {
        return -1;
    }
    sql = "CREATE TABLE " + access_table + " (hasAccessType " + 
          PRINCTYPE + ", hasAccessValue " PRINCVALUE
          ", accessToType " + PRINCTYPE + ", accessToValue "
          PRINCVALUE ", Sym_Key " TN_SYM_KEY ", Salt " TN_SALT
          ", Asym_Key " TN_PK_KEY ", PRIMARY KEY (hasAccessType," +
          " hasAccessValue, accessToType, accessToValue), " +
          "KEY (accessToType, accessToValue))";
    if (execute(sql) < 0) {
        return -1;
    }
    return 0;
}

int
MetaAccess::DeleteTables()
{
    string sql, num;
    map<string, std::set<string> >::iterator it;
    std::set<string>::iterator it_s;
    //Public Keys table
    //TODO: fix PRINCVALUE to be application specific
    sql = "DROP TABLE IF EXISTS " + public_table + ";";
    execute(sql);
    //Access Keys table
    sql = "DROP TABLE IF EXISTS " + access_table + ";";
    execute(sql);
    return 0;
}

MetaAccess::~MetaAccess()
{
    DeleteTables();
    prinToGen.clear();
    genToPrin.clear();
    genHasAccessToList.clear();
    genAccessibleByList.clear();
    givesPsswd.clear();
}

void
MetaAccess::PrintMaps()
{
    map<string, string>::iterator it_m;
    map<string, std::set<string> >::iterator it_ms;
    std::set<string>::iterator it_s;

    cerr << "Principal --> Generic" << endl;
    for(it_m = prinToGen.begin(); it_m != prinToGen.end(); it_m++) {
        cerr << "  "  << it_m->first << "->" << it_m->second << endl;
    }

    cerr << "Generic --> Principal" << endl;
    for(it_ms = genToPrin.begin(); it_ms != genToPrin.end(); it_ms++) {
        cerr << "  " << it_ms->first << "->";
        for(it_s = it_ms->second.begin(); it_s != it_ms->second.end();
            it_s++) {
            cerr << *it_s << " ";
        }
        cerr << endl;
    }

    cerr << "Principal ---can access---> Principal" << endl;
    for(it_ms = genHasAccessToList.begin(); it_ms != genHasAccessToList.end();
        it_ms++) {
        cerr << "  " << it_ms->first << "->";
        for(it_s = it_ms->second.begin(); it_s != it_ms->second.end();
            it_s++) {
            cerr << *it_s << " ";
        }
        cerr << endl;
    }

    cerr << "Principal <---can access--- Principal" << endl;
    for(it_ms = genAccessibleByList.begin(); it_ms != genAccessibleByList.end();
        it_ms++) {
        cerr << "  " << it_ms->first << "->";
        for(it_s = it_ms->second.begin(); it_s != it_ms->second.end();
            it_s++) {
            cerr << *it_s << " ";
        }
        cerr << endl;
    }

    cerr << "Gives Password:\n  ";
    for(it_s = givesPsswd.begin(); it_s != givesPsswd.end(); it_s++) {
        cerr << *it_s << " ";
    }
    cerr << endl;
}

//------------------------------------------------------------------------------------------

KeyAccess::KeyAccess(Connect * connect)
{
    this->VERBOSE = VERBOSE_KEYACCESS;
    this->meta = new MetaAccess(connect, VERBOSE);
    this->crypt_man = new CryptoManager(randomBytes(AES_KEY_BYTES));
    this->conn = connect;
    this->meta_finished = false;
}

ResType
KeyAccess::execute(string sql) {
    DBResult * dbres;
    if (!conn->execute(sql, dbres)) {
        LOG(am) << "SQL error with query: " << sql;
        return ResType(false);
    }
    ResType res = dbres->unpack();
    delete dbres;
    return res;
}

int
KeyAccess::addEquals(string prin1, string prin2)
{
    if (meta_finished) {
        //there will only be key conflicts if both prin1 and prin2 are existing principals
        //  that have access to keys and they already have instances with the same values
        string gen1 = getGeneric(prin1);
        string gen2 = getGeneric(prin2);
        if (gen1 != "" && gen2 != "") {
            string sql = "SELECT DISTINCT hasAccessType, hasAccessValue, accessToType, accessToValue FROM " + meta->accessTableName() + " WHERE hasAccessType = '" + gen1 + "' OR hasAccessType = '" + gen2 + "' OR accessToType = '" + gen1 + "' OR accessToType = '" + gen2 + "'";
            ResType res = execute(sql);
            std::set<string> prin1_values;
            std::set<string> prin2_values;
            std::set<Prin> prin1_hasaccess;
            std::set<Prin> prin2_hasaccess;
            for(auto it = res.rows.begin(); it != res.rows.end(); it++) {
                if (it->at(0).data == gen1) {
                    if (prin2_values.find(it->at(1).data) != prin2_values.end()) {
                        LOG(am) << "addEquals failed: the new equals would alter the currently exist key links";
                        return -1;
                    }
                    prin1_values.insert(it->at(1).data);
                } else if (it->at(0).data == gen2) {
                    if (prin1_values.find(it->at(1).data) != prin1_values.end()) {
                        LOG(am) << "addEquals failed: the new equals would alter the currently exist key links";
                        return -1;
                    }
                    prin2_values.insert(it->at(1).data);
                }
            }
        }
        string old1 = getGeneric(prin1);
        string old2 = getGeneric(prin2);
        if (meta->addEqualsCheck(prin1, prin2) < 0) {
            return -1;
        }
        updateMaps(old1, old2, getGeneric(prin1));
        return 0;
    }

    meta->addEquals(prin1, prin2);
    return 0;
}

void
KeyAccess::updateMaps(string old1, string old2, string gen) {
    //note that we only really need to check for old2, since addEquals
    // links both prins to the first prin's generic if both existed befor
    
    assert_s((old1 != "" && old1 == gen) || (old1 == "" && old2 != "" && old2 == gen) || (old1 == "" && old2 == ""), "addEquals chose teh wrong gen...");

    //keys
    set<Prin> new_keys;
    for(auto k = keys.begin(); k != keys.end(); k++) {
        if (k->first.gen == old1) {
            new_keys.insert(k->first);
        }
        if (k->first.gen == old2) {
            new_keys.insert(k->first);
        }
    }
    for(auto k = new_keys.begin(); k != new_keys.end(); k++) {
        Prin k_new;
        k_new.value = k->value;
        k_new.gen = gen;
        keys[k_new] = keys[*k];
        keys.erase(*k);
    }
    auto k = uncached_keys.begin();


    //uncached_keys
    while((k = uncached_keys.find(old2)) != uncached_keys.end()) {
        uncached_keys[gen] = k->second;
        if (k->first != gen) {
            uncached_keys.erase(k->first);
        }
    }
    for (auto u = uncached_keys.begin(); u != uncached_keys.end(); u++) {
        auto uk = u->second.begin();
        while((uk = u->second.find(old2)) != u->second.end()) {
            u->second[gen] = uk->second;
            if (uk->first != gen) {
                uncached_keys.erase(uk->first);
            }
        }
    }
        

    //orphansToParents
    set<Prin> first_tier;
    for (auto o = orphanToParents.begin(); o != orphanToParents.end(); o++) {
        if (o->first.gen == old2) {
            first_tier.insert(o->first);
        }
        set<Prin> second_tier;
        for (auto parent = o->second.begin(); parent != o->second.end(); parent++) {
            if (parent->gen == old2) {
                second_tier.insert(*parent);
            }
        }
        for (auto parent = second_tier.begin(); parent != second_tier.end(); parent++) {
            Prin new_gen;
            new_gen.gen = gen;
            new_gen.value = parent->value;
            o->second.erase(*parent);
            o->second.insert(new_gen);
        }
    }
    for (auto o = first_tier.begin(); o != first_tier.end(); o++) {
        Prin new_gen;
        new_gen.gen = gen;
        new_gen.value = o->value;
        orphanToParents[new_gen] = orphanToParents[*o];
        orphanToParents.erase(*o);
    }


    //orphansToParents
    first_tier.clear();
    for (auto o = orphanToChildren.begin(); o != orphanToChildren.end(); o++) {
        if (o->first.gen == old2) {
            first_tier.insert(o->first);
        }
        set<Prin> second_tier;
        for (auto child = o->second.begin(); child != o->second.end(); child++) {
            if (child->gen == old2) {
                second_tier.insert(*child);
            }
        }
        for (auto child = second_tier.begin(); child != second_tier.end(); child++) {
            Prin new_gen;
            new_gen.gen = gen;
            new_gen.value = child->value;
            o->second.erase(*child);
            o->second.insert(new_gen);
        }
    }
    for (auto o = first_tier.begin(); o != first_tier.end(); o++) {
        Prin new_gen;
        new_gen.gen = gen;
        new_gen.value = o->value;
        orphanToChildren[new_gen] = orphanToChildren[*o];
        orphanToChildren.erase(*o);
    }
}

int
KeyAccess::addAccess(string hasAccess, string accessTo)
{
    if (meta_finished) {
        return meta->addAccessCheck(hasAccess, accessTo);
    }

    meta->addAccess(hasAccess, accessTo);
    return 0;
}

int
KeyAccess::addGives(string prin)
{
    if (meta_finished) {
        return meta->addGivesCheck(prin);
    }

    meta->addGives(prin);
    return 0;
}

int
KeyAccess::CreateTables()
{
    if (meta_finished) {
        LOG(am) << "ERROR: trying to create tables after meta is finished";
        return -1;
    }

    return meta->CreateTables();
}

int
KeyAccess::DeleteTables()
{
    return meta->DeleteTables();
}

std::set<string>
KeyAccess::getTypesAccessibleFrom(string princ)
{
    return meta->getTypesAccessibleFrom(princ);
}
std::set<string>
KeyAccess::getGenAccessibleFrom(string princ)
{
    return meta->getGenAccessibleFrom(princ);
}
std::set<string>
KeyAccess::getTypesHasAccessTo(string princ)
{
    return meta->getTypesHasAccessTo(princ);
}
std::set<string>
KeyAccess::getGenHasAccessTo(string princ)
{
    return meta->getGenHasAccessTo(princ);
}
std::set<string>
KeyAccess::getEquals(string princ)
{
    return meta->getEquals(princ);
}

string
KeyAccess::getGeneric(string prin)
{
    return meta->getGenericPublic(prin);
}

void
KeyAccess::Print()
{
    return meta->PrintMaps();
}

int
KeyAccess::insert(Prin hasAccess, Prin accessTo)
{    
    if (!meta_finished) {
        LOG(am) << "meta concluded" << endl;
        if(CreateTables() < 0) {
            return -1;
        }
    }    

    if (VERBOSE) {
        LOG(am_v) << "insert(" << hasAccess.type << "=" << hasAccess.value <<
        "," << accessTo.type << "=" << accessTo.value << ")";
    }

    //check that we're not trying to generate a
    assert_s(!(meta->isGives(hasAccess.type) &&
               (getKey(hasAccess).length() > 0) && !isInstance(
                   hasAccess)), "cannot create a givesPsswd key");

    hasAccess.gen = meta->getGenericPublic(hasAccess.type);
    accessTo.gen = meta->getGenericPublic(accessTo.type);
    string table = meta->accessTableName();
    string sql;

    if (SelectAccess(hasAccess, accessTo).rows.size() > 0) {
        if (VERBOSE) {
            LOG(am_v) << "relation " + hasAccess.gen + "=" +
            hasAccess.value +
            "->" + accessTo.gen + "=" + accessTo.value + " already exists";
        }
        return 1;
    }

    //Get key for this accessTo
    string accessToKey;
    bool already_in_keys = false;

    //check to see if we already hold keys
    if (keys.find(accessTo) != keys.end()) {
        if (VERBOSE) {
            LOG(am_v) << "key for " + accessTo.gen + "=" + accessTo.value +
            " is already held";
        }
        keys[accessTo].principals_with_access.insert(hasAccess);
        accessToKey = keys[accessTo].key;
        already_in_keys = true;
    }

    //see if there are any entries with the same second field
    Prin empty;
    ResType resultset = SelectAccess(empty, accessTo);
    //keys for this link exist; decrypt them
    if(resultset.rows.size() > 0) {
        auto it = resultset.rows.begin();
        for(; it != resultset.rows.end(); it++) {
            Prin this_row;
            this_row.type = hasAccess.type;
            this_row.gen = hasAccess.gen;
            this_row.value = it->at(1).data;
            string key_for_decryption = getKey(this_row);
            if (key_for_decryption.length() > 0) {
                PrinKey accessToPrinKey = decryptSym(it->at(4),
                                                     key_for_decryption,
                                                     it->at(5));
                accessToKey = accessToPrinKey.key;
                break;
            }
        }
    }
    //keys for this link don't exist; generate them
    else if (!already_in_keys) {
        accessToKey = randomBytes(AES_KEY_BYTES);
    }

    if(accessToKey.length() == 0) {
        LOG(am) << "ERROR: cannot decrypt this key";
        return -1;
    }

    //get sym key for hasAccess
    PrinKey hasAccessPrinKey;
    string hasAccessKey;
    //if orphan, getPrinKey will generate key
    hasAccessPrinKey = getPrinKey(hasAccess);
    hasAccessKey = hasAccessPrinKey.key;
    string encrypted_accessToKey;
    string string_encrypted_accessToKey;

    if(hasAccessKey.length() != 0) {
        uint64_t salt = randomValue();
        AES_KEY * aes = get_AES_enc_key(hasAccessKey);
        encrypted_accessToKey = encrypt_AES_CBC(accessToKey, aes, BytesFromInt(salt, SALT_LEN_BYTES));
        string string_salt = strFromVal(salt);
        string_encrypted_accessToKey = marshallBinary(encrypted_accessToKey);
        sql = "INSERT INTO " + table + "(hasAccessType, hasAccessValue, " + 
              "accessToType, accessToValue, Sym_Key, Salt) VALUES ('" +
              hasAccess.gen + "', '" + hasAccess.value + "', '" +
              accessTo.gen + "', '" + accessTo.value + "', " +
              string_encrypted_accessToKey + ", " + string_salt + ");";
    }
    //couldn't get symmetric key for hasAccess, so get public key
    else {
        PKCS * hasAccess_publicKey = getPublicKey(hasAccess);
        assert_s(hasAccess_publicKey, "Could not access public key");
        encrypted_accessToKey = crypt_man->encrypt(hasAccess_publicKey,
                                                   accessToKey);
        string_encrypted_accessToKey = marshallBinary(encrypted_accessToKey);
        sql = "INSERT INTO " + table + "(hasAccessType, hasAccessValue, " +
              "accessToType, accessToValue, Asym_Key) VALUES ('" +
              hasAccess.gen + "', '" + hasAccess.value + "', '" +
              accessTo.gen + "', '" + accessTo.value + "', " + 
              string_encrypted_accessToKey + ");";
    }

    //update table with encrypted key
    if(!conn->execute(sql)) {
        LOG(am) << "Problem with sql statement: " << sql;
        return -1;
    }

    //store key locally if either user is logged on
    PrinKey accessToPrinKey = buildKey(hasAccess, accessToKey);
    accessToPrinKey.principals_with_access.insert(accessTo);
    if (!already_in_keys &&
        (getKey(hasAccess).length() > 0 || getKey(accessTo).length() > 0)) {
        addToKeys(accessTo, accessToPrinKey);
    }

    //check that accessTo has publics key; if not generate them
    if (!isInstance(accessTo)) {
        GenerateAsymKeys(accessTo,accessToPrinKey);
    }

    //orphans
    std::set<Prin> hasAccess_set;
    hasAccess_set.insert(hasAccess);
    std::set<Prin> accessTo_set;
    accessTo_set.insert(accessTo);
    bool hasAccess_has_children =
        (orphanToChildren.find(hasAccess) != orphanToChildren.end());
    bool accessTo_has_parents =
        (orphanToParents.find(accessTo) != orphanToParents.end());

    if (!isInstance(hasAccess)) {
        //add to orphan graphs
        orphanToParents[accessTo] = hasAccess_set;
        orphanToChildren[hasAccess] = accessTo_set;
        //set up asymmetric encryption
        ResType res = SelectPublic(hasAccess);

        assert_s(
            hasAccessPrinKey.key.length() > 0, "created hasAccess has no key");
        if (res.rows.size() == 0)
            GenerateAsymKeys(hasAccess,hasAccessPrinKey);

        addToKeys(accessTo, accessToPrinKey);
        addToKeys(hasAccess, hasAccessPrinKey);
        assert_s(isOrphan(
                     hasAccess), "orphan principal is not checking as orphan");
        assert_s(isInstance(
                     hasAccess),
                 "orphan hasAccess thinks it doesn't exist >_<");
        return 0;
    }

    //if it was an orphan, remove it from the orphan graphs
    // first check if hasAccess is online, and if not, remove keys from local memory
    if (isOrphan(accessTo) && !isOrphan(hasAccess)) {
        return removeFromOrphans(accessTo);
    }


    if (isOrphan(hasAccess)) {
        if (hasAccess_has_children) {
            orphanToChildren[hasAccess].insert(accessTo);
        } else {
            orphanToChildren[hasAccess] = accessTo_set;
        }
        if (accessTo_has_parents) {
            orphanToParents[accessTo].insert(hasAccess);
        } else {
            orphanToParents[accessTo] = hasAccess_set;
        }
        if (!already_in_keys) {
            addToKeys(accessTo, accessToPrinKey);
        }
        return 0;
    }


    assert_s(isInstance(
                 hasAccess), "hasAccess does not exist; this is an orphan");

    return 0;
}

int
KeyAccess::remove(Prin hasAccess, Prin accessTo)
{
    if(VERBOSE) {
        LOG(am_v) << "remove(" << hasAccess.type << "=" << hasAccess.value <<
        "," << accessTo.type << "=" << accessTo.value << ")";
    }

    if(hasAccess.gen == "") {
        hasAccess.gen = meta->getGenericPublic(hasAccess.type);
    }
    if(accessTo.gen == "") {
        accessTo.gen = meta->getGenericPublic(accessTo.type);
    }

    assert_s(isInstance(
                 hasAccess), "hasAccess in remove is has not been inserted");
    assert_s(isInstance(
                 accessTo), "accessTo in remove is has not been inserted");

    //remove hasAccess from accessTo's principals_with_access if local key is
    // stored
    if (getKey(accessTo).length() > 0) {
        PrinKey accessTo_key = keys[accessTo];
        accessTo_key.principals_with_access.erase(hasAccess);
        keys[accessTo] = accessTo_key;
        //if this was the only link keeping accessTo's key accessible, delete
        // the entire subtree
        if (accessTo_key.principals_with_access.size() <= 1) {
            return removePsswd(accessTo);
        }
    }

    //remove hasAccess from accessTo's table
    return RemoveRow(hasAccess, accessTo);

    return 0;
}

int
KeyAccess::removeFromOrphans(Prin orphan)
{
    //remove descendants from orphanToChildren
    if(VERBOSE) {
        LOG(am_v) << "   removing " << orphan.gen << "=" << orphan.value <<
        " from orphans";
    }
    list<Prin> children;
    std::set<Prin>::iterator it;
    children.push_back(orphan);
    for(it = orphanToChildren[orphan].begin();
        it != orphanToChildren[orphan].end(); it++) {
        children.push_back(*it);
    }
    list<Prin>::iterator child = children.begin();
    map<Prin, std::set<Prin> >::iterator it_map = orphanToParents.begin();
    while (child != children.end()) {
        if (orphanToChildren.find(*child) != orphanToChildren.end()) {
            for (it = orphanToChildren[*child].begin();
                 it != orphanToChildren[*child].end(); it++) {
                children.push_back(*it);
            }
        }
        child++;
    }
    for (child = children.begin(); child != children.end(); child++) {
        if (orphanToChildren.find(*child) != orphanToChildren.end()) {
            orphanToChildren.erase(*child);
        }
        if (orphanToParents.find(*child) != orphanToParents.end()) {
            orphanToParents.erase(*child);
        }
    }

    //remove descendants from orphanToParents
    while (it_map != orphanToParents.end()) {
        if (inList(children, it_map->first)) {
            orphanToParents.erase(it_map->first);
        }
        it_map++;
    }

    //check to see if orphans' keys should be accessible
    std::set<Prin>::iterator princ_access;
    for (princ_access = keys[orphan].principals_with_access.begin();
         princ_access != keys[orphan].principals_with_access.end();
         princ_access++) {
        if (keys.find(*princ_access) != keys.end() && *princ_access !=
            orphan) {
            return 0;
        }
    }
    for (child = children.begin(); child != children.end(); child++) {
        keys.erase(*child);
    }
    keys.erase(orphan);
    return 0;
}

string
KeyAccess::getKey(Prin prin)
{
    if(prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }
    LOG(am_v) << "getKey (" << prin.gen << ", " << prin.value << ") \n";
    PrinKey prinkey = getPrinKey(prin);
    if(VERBOSE) {
        LOG(am_v) << "     " << prin.gen  << "=" << prin.value
                  << " has principals with access: ";
        std::set<Prin>::iterator it;
        for(it = prinkey.principals_with_access.begin();
            it != prinkey.principals_with_access.end(); it++) {
            LOG(am_v) << "\t" << it->gen << "=" << it->value;
        }
    }
    //cerr << "returning null? " << (prinkey.key.length() == 0) << "\n";
    return prinkey.key;
}

PrinKey
KeyAccess::getPrinKey(Prin prin)
{
    if(prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }

    if(VERBOSE) {
        LOG(am_v) << "   fetching key for " << prin.gen << " " <<
        prin.value;
    }

    if(keys.find(prin) != keys.end()) {
        assert_s(
            keys[prin].key.length() == AES_KEY_BYTES,
            "getKey is trying to return a key of the wrong length");
        LOG(am_v) << "got key from local map";
        return keys[prin];
    }

    PrinKey prinkey;

    //is orphan
    if (!isInstance(prin)) {
        string key = randomBytes(AES_KEY_BYTES);
        prinkey = buildKey(prin, key);
        addToKeys(prin, prinkey);
        GenerateAsymKeys(prin, prinkey);
        std::set<Prin> empty_set;
        orphanToParents[prin] = empty_set;
        orphanToChildren[prin] = empty_set;
        assert_s(isInstance(
                     prin),
                 "newly created orphan in getKey is not recognized as an instance");
        assert_s(isOrphan(
                     prin),
                 "newly created orphan in getKey is not recognized as an orphan");
        return prinkey;
    }

    prinkey = getUncached(prin);
    if (prinkey.key.length() != 0) {
        return prinkey;
    }

    if (VERBOSE) {
        LOG(am_v) << "asking for a key that exists but is not accessible: "
             << prinkey.key.length();
    }

    return prinkey;
}

PKCS *
KeyAccess::getPublicKey(Prin prin)
{
    if(VERBOSE) {
        LOG(am_v) << "   getting public key for " << prin.gen << " " <<
        prin.value;
    }
    assert_s(isInstance(
                 prin),
             "prin input to getPublicKey has never been seen before");
    assert_s(prin.gen != "",
             "input into getPublicKey has an undefined generic");
    ResType res = SelectPublic(prin);

    if(res.rows.size() == 0) {
        LOG(am) << "No public key for input to getPublicKey";
        return NULL;
    }

    string key = res.rows[0][2].data;
    return crypt_man->unmarshallKey(key, true);
}

PrinKey
KeyAccess::getSecretKey(Prin prin)
{
    PrinKey error;

    if(VERBOSE) {
        LOG(am_v) << "   fetching secret key";
    }
    assert_s(isInstance(
                 prin),
             "prin input to getSecretKey has never been seen before");
    assert_s(prin.gen != "",
             "input into getSecretKey has an undefined generic");
    ResType res = SelectPublic(prin);

    if(res.rows.size() == 0) {
        LOG(am) << "No public key for input to getSecretKey";
        return error;
    }

    return decryptSym(res.rows[0][3], getKey(prin), res.rows[0][4]);
}

int
KeyAccess::insertPsswd(Prin gives, const string &psswd)
{
    if (!meta_finished) {
        LOG(am) << "meta concluded" << endl;
        if(CreateTables() < 0) {
            return -1;
        }
    }

    if(VERBOSE) {
        LOG(am_v) << gives.type << " " << gives.value
                  << " is logging in with " << stringToByteInts(psswd);
        LOG(am_v) << "insertPsswd(" << gives.type << "=" << gives.value << ",...)";
    }

    int ret = 0;

    gives.gen = meta->getGenericPublic(gives.type);
    std::set<string> gives_hasAccessTo = meta->getGenHasAccessTo(gives.gen);


    // put password into local keys
    PrinKey password = buildKey(gives, psswd);
    int is_new_key = addToKeys(gives, password);

    if (is_new_key < 0) {
        LOG(am) << gives.type << " " << gives.value << " tried to log in with wrong password";
        return -1;
    } else if (is_new_key > 0) {
        LOG(am) << gives.type << " " << gives.value << " is already logged in; not loading keys";
        return 1;
    }

    //check if this person has a asym key (that is, if gives is an instance
    // that has been inserted before)
    if (!isInstance(gives)) {
        GenerateAsymKeys(gives, password);
        return 0;
    }

    //get a list of all possible gens gives could access
    list<string> gives_hasAccess = DFS_hasAccess(gives);

    //sort through the list, getting keys if they exist, and decrypting and
    // storing them
    list<string>::iterator accessTo = gives_hasAccess.begin();
    list<string>::iterator hasAccess = gives_hasAccess.begin();
    accessTo++;
    std::set<Prin> accessible_values;
    std::set<Prin> values;
    accessible_values.insert(gives);
    for (hasAccess = gives_hasAccess.begin();
         hasAccess != gives_hasAccess.end(); hasAccess++) {
        for (accessTo = gives_hasAccess.begin();
             accessTo != gives_hasAccess.end(); accessTo++) {
            std::set<string> acc_to = meta->getGenHasAccessTo(*hasAccess);
            std::set<string>::iterator i;
            if (acc_to.find(*accessTo) == acc_to.end() || accessTo ==
                hasAccess) {
                continue;
            }
            Prin hasAccess_prin;
            std::set<Prin>::iterator v;
            for (v = accessible_values.begin(); v != accessible_values.end();
                 v++) {
                if (hasAccess->compare(v->gen) == 0) {
                    values.insert(*v);
                }
            }
            for (v = values.begin(); v != values.end(); v++) {
                hasAccess_prin = *v;
                assert_s(hasAccess->compare(
                             hasAccess_prin.gen) == 0,
                         "hasAccess_prin in insertPsswd is WRONG");
                //cerr << "\t" << v->gen << "=" << v->value << endl;
                Prin empty;
                int number_keys = SelectAccessCount(hasAccess_prin, empty);
                //if there are many keys of this type, don't store them in
                // local memory
                if (number_keys > THRESHOLD) {
                    if (VERBOSE) {
                        LOG(am_v) << "caching " << number_keys << " for " <<
                        *accessTo;
                    }
                    if (uncached_keys.find(*accessTo) !=
                        uncached_keys.end() && uncached_keys[*accessTo].find(hasAccess_prin.gen) != uncached_keys[*accessTo].end()) {
                        uncached_keys[*accessTo][hasAccess_prin.gen]++;
                    } else {
                        uncached_keys[*accessTo][hasAccess_prin.gen] = 1;
                    }
                    continue;
                }
                ResType res = SelectAccess(hasAccess_prin, empty);
                //cerr << "res okay " << res.rows.size() << " for " << hasAccess_prin.gen << "=" << hasAccess_prin.value << endl;
                if (res.rows.size() > 0) {
                    auto row = res.rows.begin();
                    while (row != res.rows.end()) {
                        //remember to check this Prin on the next level
                        Prin new_prin;
                        //accessTo prin
                        new_prin.gen = row->at(2).data;
                        new_prin.value = row->at(3).data;
                        //cerr << "  new_prin: " << new_prin.gen << "=" << new_prin.value << endl;
                        accessible_values.insert(new_prin);
                        string new_key = getKey(new_prin);
                        //cerr << "  new_key: " << new_key << endl;
                        PrinKey new_prin_key;
                        //if key is not currently held by anyone
                        if (new_key.length() == 0) {
                            assert_s(getKey(
                                         hasAccess_prin).length() > 0,
                                     "there is a logical issue with insertPsswd: getKey should have the key for hasAccess");
                            //cerr << row->at(0).data << "=" << row->at(1).data << " ---> " << row->at(2).data << "=" << row->at(3).data << endl;
                            if (row->at(6).null || row->at(6).data.size() == 0) {
                                // symmetric key okay
                                new_prin_key =
                                    decryptSym(row->at(4), getKey(
                                                   hasAccess_prin), row->at(5));
                            } else {
                                // use asymmetric
                                PrinKey sec_key = getSecretKey(hasAccess_prin);
                                new_prin_key = decryptAsym(row->at(6),
                                                           sec_key.key);
                            }
                            //cerr << "\t got key: " << new_prin_key.key << endl;
                        }
                        //if key is currently held by someone else...
                        else {
                            new_prin_key = buildKey(new_prin, new_key);
                        }
                        //cerr << "\t   c" << endl;
                        new_prin_key.principals_with_access.insert(new_prin);
                        new_prin_key.principals_with_access.insert(
                            hasAccess_prin);
                        if (addToKeys(new_prin, new_prin_key) < 0) {
                            ret--;
                        }
                        row++;
                    }
                }
            }
            values.clear();
        }
    }

    return ret;
}

int
KeyAccess::removePsswd(Prin prin)
{
    if(VERBOSE) {
        LOG(am_v) << "removePsswd(" << prin.type << "=" << prin.value << ")";
    }

    if(prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }

    assert_s(isInstance(prin), "prin in removePsswd is has not been inserted");

    list<string> hasAccessTo = BFS_hasAccess(prin);
    list<string>::iterator hasAccessTo_gen;
    map<Prin, PrinKey>::iterator key_it;
    std::set<Prin> remove_set;
    remove_set.insert(prin);
    std::set<Prin>::iterator set_it;

    for (hasAccessTo_gen = hasAccessTo.begin();
         hasAccessTo_gen != hasAccessTo.end(); hasAccessTo_gen++) {
        for (key_it = keys.begin(); key_it != keys.end(); key_it++) {
            if (key_it->first.gen == *hasAccessTo_gen) {
                for (set_it = remove_set.begin(); set_it != remove_set.end();
                     set_it++) {
                    if (key_it->second.principals_with_access.find(*set_it)
                        != key_it->second.principals_with_access.end()) {
                        key_it->second.principals_with_access.erase(*set_it);
                        if (key_it->second.principals_with_access.size() <=
                            1) {
                            remove_set.insert(key_it->first);
                        }
                    }
                }
            }
        }
    }

    std::set<string> remove_uncached;
    for(set_it = remove_set.begin(); set_it != remove_set.end(); set_it++) {
        for(auto map_it = uncached_keys.begin(); map_it != uncached_keys.end();
            map_it++) {
            auto rem_it = map_it->second.find(set_it->gen);
            if (rem_it != map_it->second.end()) {
                if (rem_it->second <= 1) {
                    map_it->second.erase(set_it->gen);
                } else {
                    rem_it->second--;
                }
            }
            if (map_it->second.size() <= 1) {
                remove_uncached.insert(map_it->first);
            }
        }
        removeFromKeys(*set_it);
    }
    for (auto rem = remove_uncached.begin(); rem != remove_uncached.end(); rem++) {
        uncached_keys.erase(*rem);
    }

    return 0;
}

PrinKey
KeyAccess::buildKey(Prin hasAccess, const string &sym_key)
{
    PrinKey new_key;
    new_key.key = sym_key;
    std::set<Prin> prinHasAccess;
    prinHasAccess.insert(hasAccess);
    new_key.principals_with_access = prinHasAccess;
    return new_key;
}

int
KeyAccess::addToKeys(Prin prin, PrinKey key)
{
    if (prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }
    assert_s(key.principals_with_access.find(
                 prin) != key.principals_with_access.end(),
             "addToKeys hasAccess prin is not in key's principals_with_access");
    if(VERBOSE) {
        LOG(am_v) << "adding key " << stringToByteInts(key.key)
                  << " for " << prin.gen << " " << prin.value;
    }

    if (keys.find(prin) != keys.end()) {
        if (keys[prin] == key) {
            std::set<Prin>::iterator it;
            for(it = key.principals_with_access.begin();
                it != key.principals_with_access.end(); it++) {
                keys[prin].principals_with_access.insert(*it);
            }
            return 1;
        }
        else {
            LOG(am) << "prin input to addToKeys already has a different key";
            return -1;
        }
    }

    keys[prin] = key;

    std::set<Prin>::iterator set_it;
    map<Prin, PrinKey>::iterator key_it;
    int count = 0;
    int users = 0;
    for (key_it = keys.begin(); key_it != keys.end(); key_it++) {
        for (set_it = key.principals_with_access.begin();
             set_it != key.principals_with_access.end(); set_it++) {
            if (key_it->first.gen.compare(set_it->gen) == 0) {
                count++;
            }
        }
        if (meta->isGenGives(key_it->first.gen)) {
            users++;
        }
    }
    if (users > 0) {
        count /= users;
    }
    if (count > THRESHOLD) {
        LOG(am) << "WARNING: more than " << THRESHOLD <<
        " keys on average per user of the same type have been added to the local map";
    }

    return 0;
}

int
KeyAccess::removeFromKeys(Prin prin)
{
    if(prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }

    if(VERBOSE) {
        LOG(am_v) << "   removing key for " << prin.gen << " " << prin.value;
    }

    //remove all this prin's uncached key references
    if (uncached_keys.find(prin.gen) != uncached_keys.end()) {
        map<string, int> typeHasAccess = uncached_keys.find(prin.gen)->second;
        std::set<Prin> prin_set;
        //prin_set.insert(*set_it);
        prin_set.insert(prin);
        for (auto set_it = typeHasAccess.begin(); set_it != typeHasAccess.end();
             set_it++) {
            Prin empty;
            ResType res = SelectAccess(prin, empty);
            bool erase = true;
            for (auto row = res.rows.begin(); row != res.rows.end(); row++) {
                if (row->at(0).data != set_it->first) {
                    erase = false;
                }
            }
            if (erase) {
                uncached_keys[prin.gen].erase(set_it->first);
            }
        }
        if (uncached_keys[prin.gen].empty()) {
            uncached_keys.erase(prin.gen);
        }
    }

    if (keys.find(prin) == keys.end()) {
        if(VERBOSE) {
            LOG(am_v) << "prin input to removeFromKeys does not have key";
        }
        return 1;
    }

    keys[prin].key.resize(0);
    keys.erase(prin);
    return 0;
}

list<string>
KeyAccess::BFS_hasAccess(Prin start)
{
    if(start.gen == "") {
        start.gen = meta->getGenericPublic(start.type);
    }

    list<string> results;
    std::set<string> current_layer = meta->getGenHasAccessTo(start.gen);
    std::set<string> next_layer;
    std::set<string>::iterator current_node;
    std::set<string>::iterator next_node;

    results.push_back(start.gen);

    for(current_node = current_layer.begin();
        current_node != current_layer.end(); current_node++) {
        if (!inList(results,*current_node)) {
            results.push_back(*current_node);
        }
    }

    while(current_layer.size() != 0) {
        for(current_node = current_layer.begin();
            current_node != current_layer.end(); current_node++) {
            std::set<string> next = meta->getGenHasAccessTo(*current_node);
            for(next_node = next.begin(); next_node != next.end();
                next_node++) {
                if (!inList(results,*next_node)) {
                    results.push_back(*next_node);
                    next_layer.insert(*next_node);
                }
            }
        }
        current_layer = next_layer;
        next_layer.clear();
    }

    return results;
}

list<string>
KeyAccess::DFS_hasAccess(Prin start)
{
    if(start.gen == "") {
        start.gen = meta->getGenericPublic(start.type);
    }

    list<string> results;
    std::set<string> reachable_from_current = meta->getGenHasAccessTo(
        start.gen);
    list<string> to_investigate;
    string current_node;
    std::set<string>::iterator it;

    results.push_back(start.gen);

    for(it = reachable_from_current.begin(); it != reachable_from_current.end();
        it++) {
        if(!inList(results,*it)) {
            to_investigate.push_back(*it);
        }
    }

    while(to_investigate.size() > 0) {
        current_node = to_investigate.front();
        to_investigate.pop_front();
        while(inList(results, current_node)) {
            if (to_investigate.empty()) {
                return results;
            }
            current_node = to_investigate.front();
            to_investigate.pop_front();
        }
        results.push_back(current_node);
        reachable_from_current = meta->getGenHasAccessTo(current_node);
        for(it = reachable_from_current.begin();
            it != reachable_from_current.end(); it++) {
            if (!inList(results, *it)) {
                to_investigate.push_front(*it);
            }
        }
    }

    return results;
}

ResType
KeyAccess::SelectAccess(Prin hasAccess, Prin accessTo)
{
    return SelectAccessCol(hasAccess, accessTo, "*");
}

int
KeyAccess::SelectAccessCount(Prin hasAccess, Prin accessTo)
{
    auto res = SelectAccessCol(hasAccess, accessTo, "COUNT(*)");
    return (int) valFromStr(res.rows[0][0].data);
}

ResType
KeyAccess::SelectPublic(Prin prin)
{
    return SelectPublicCol(prin, "*");
}

int
KeyAccess::SelectPublicCount(Prin prin)
{
    auto res = SelectPublicCol(prin, "COUNT(*)");
    return (int) valFromStr(res.rows[0][0].data);
}

ResType
KeyAccess::SelectAccessCol(Prin hasAccess, Prin accessTo, string column)
{
    assert_s(hasAccess.gen != "" || accessTo.gen != "", "Select received two empty arguments");
    string sql = "SELECT " + column + " FROM " + meta->accessTableName() + " WHERE ";
    if (hasAccess.gen != "") {
        sql += "hasAccessType = '" + hasAccess.gen + "' AND hasAccessValue = '" +
               hasAccess.value + "'";
        if (accessTo.gen != "") {
            sql += " AND ";
        }
    }
    if (accessTo.gen != "") {
        sql += "accessToType = '" + accessTo.gen + "' AND accessToValue = '" +
               accessTo.value + "'";
    }
    sql += ";";
    LOG(am_v) << sql;
    return execute(sql);
}

ResType
KeyAccess::SelectPublicCol(Prin prin, string column)
{
    assert_s(prin.gen != "", "prin argument to SelectPublic or SelectPublicCount has no gen");
    string sql = "SELECT " + column + " FROM " + meta->publicTableName() + 
                 " WHERE Type = '" + prin.gen + "' AND Value = '" + prin.value + "'";
    return execute(sql);
}

//TODO: modify for access_table rather than multiple tables
int
KeyAccess::RemoveRow(Prin hasAccess, Prin accessTo)
{
    assert_s(hasAccess.gen != "", "hasAccess input to RemoveRow has no gen");
    assert_s(accessTo.gen != "", "accessTo input to RemoveRow has no gen");
    string sql = "DELETE FROM " + meta->accessTableName() + " WHERE hasAccessType = '" 
                 + hasAccess.gen + "' AND hasAccessValue ='" + hasAccess.value + 
                 "' AND accessToType = '" + accessTo.gen + "' AND accessToValue ='" +
                 accessTo.value + "';";
    if(!conn->execute(sql)) {
        LOG(am) << "SQL error with query: " << sql;
        return -1;
    }
    return 0;
}

int
KeyAccess::GenerateAsymKeys(Prin prin, PrinKey prin_key)
{
    meta_finished = true;
    string pub_key_string = "NULL";
    string encrypted_sec_key_string = "NULL";
    string salt_string = "NULL";
    if (meta->getGenHasAccessTo(prin.gen).size() > 1) {
        AES_KEY * aes = get_AES_enc_key(prin_key.key);
        uint64_t salt = randomValue();
        PKCS * rsa_pub_key;
        PKCS * rsa_sec_key;
        crypt_man->generateKeys(rsa_pub_key,rsa_sec_key);
        string pub_key = crypt_man->marshallKey(rsa_pub_key,true);
        string sec_key = crypt_man->marshallKey(rsa_sec_key,false);
        string encrypted_sec_key = encrypt_AES_CBC(sec_key, aes, BytesFromInt(salt, SALT_LEN_BYTES));
        salt_string = strFromVal(salt);
        encrypted_sec_key_string = marshallBinary(encrypted_sec_key);
        pub_key_string = marshallBinary(pub_key);
    }
    string sql = "INSERT INTO " + meta->publicTableName() + " VALUES ('" +
                 prin.gen + "', '" + prin.value + "', " + pub_key_string +
                 ", " +
                 encrypted_sec_key_string + ", " + salt_string + ");";
    if (!conn->execute(sql)) {
        LOG(am) << "SQL error on query " << sql;
        return -1;
    }
    return 0;
}

PrinKey
KeyAccess::decryptSym(const SqlItem &sql_encrypted_key,
                      const string &key_for_decrypting,
                      const SqlItem &sql_salt)
{
    if(VERBOSE) {
        LOG(am) << "\tuse symmetric decryption";
    }
    string encrypted_key = sql_encrypted_key.data;
    uint64_t salt = valFromStr(sql_salt.data);
    AES_KEY * aes = get_AES_dec_key(key_for_decrypting);
    string key = decrypt_AES_CBC(encrypted_key, aes, BytesFromInt(salt, SALT_LEN_BYTES));
    PrinKey result;
    result.key = key;
    return result;
}

PrinKey
KeyAccess::decryptAsym(const SqlItem &sql_encrypted_key, const string &secret_key)
{
    if(VERBOSE) {
        LOG(am) << "\tuse asymmetric decryption";
    }
    PKCS * pk_sec_key = crypt_man->unmarshallKey(secret_key, false);
    string encrypted_key = sql_encrypted_key.data;
    string key = crypt_man->decrypt(pk_sec_key, encrypted_key);
    assert_s(
        key.length() == (unsigned int) AES_KEY_BYTES,
        "Secret key is the wrong length!");
    PrinKey result;
    result.key = key;
    return result;
}

bool
KeyAccess::isInstance(Prin prin)
{
    if (prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }

    int count = SelectPublicCount(prin);
    if (count > 0) {
        return true;
    } else {
        return false;
    }
}

bool
KeyAccess::isType(string type)
{
    return (meta->getGenericPublic(type).length() != 0);
}

bool
KeyAccess::isOrphan(Prin prin)
{
    return ((orphanToParents.find(prin) != orphanToParents.end()) ||
            (orphanToChildren.find(prin) != orphanToChildren.end()));
}

PrinKey
KeyAccess::getUncached(Prin prin)
{
    if (prin.gen == "") {
        prin.gen = meta->getGenericPublic(prin.type);
    }

    if (VERBOSE) {
        LOG(am_v) << "checking for uncached keys";
    }

    PrinKey empty;

    if (uncached_keys.find(prin.gen) == uncached_keys.end()) {
        return empty;
    }

    //key could still be in db
    map<string, int> typeHasAccess = uncached_keys.find(prin.gen)->second;
    ResType res;
    for (auto set_it = typeHasAccess.begin(); set_it != typeHasAccess.end();
         set_it++) {
        Prin empty_prin;
        res = SelectAccess(empty_prin, prin);
        
        for (auto row = res.rows.begin(); row != res.rows.end(); row++) {
            Prin hasAccess;
            hasAccess.gen = set_it->first;
            hasAccess.value = row->at(1).data;
            if (keys.find(hasAccess) != keys.end()) {
                PrinKey new_prin_key;
                if (row->at(6).null || row->at(6).data.size() == 0) {
                    // symmetric key okay
                    new_prin_key = decryptSym(row->at(4), getKey(hasAccess), row->at(5));
                } else {
                    // use asymmetric
                    PrinKey sec_key = getSecretKey(hasAccess);
                    new_prin_key = decryptAsym(row->at(6), sec_key.key);
                }
                return new_prin_key;
            }
        }
    }
    return empty;
}

KeyAccess::~KeyAccess()
{
    map<Prin, PrinKey>::iterator it;
    for(it = keys.begin(); it != keys.end(); it++) {
        it->second.key.resize(0);
    }
    keys.clear();
    delete meta;
    delete crypt_man;
}
