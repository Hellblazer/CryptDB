/*
 * AccessManager.cpp
 *
 *  Created on: Dec 1, 2010
 *      Authors: cat_red, raluca
 */


#include "AccessManager.h"

#define PRINCTYPE "varchar(255)"
#define NODIGITS 4

AccessManager::AccessManager(Connect * connect) {
	this->conn = connect;
	this->VERBOSE = VERBOSE_G;
	this->table_name = "cryptdb_active";
	this->table_num = 0;
	this->crypt_man = new CryptoManager(randomBytes(AES_KEY_BYTES));
	conn->execute("DROP TABLE IF EXISTS public_keys");
	conn->execute("CREATE TABLE IF NOT EXISTS public_keys (principle varchar(255), sk "TN_PK_KEY", salt bigint, pk "TN_PK_KEY", PRIMARY KEY (principle))");
	//conn->execute("DROP TABLE IF EXISTS active0");
	//conn->execute("DROP TABLE IF EXISTS active1");
}

int AccessManager::addAccessTo(string principle, string secondary) {

	//limit of 2^100 active tables --> somehow that seems sufficient
	if(VERBOSE) {
		cerr << "=> Record " << principle << " accessTo " << secondary << endl;
	}
	string gives = PrunePeriods(principle);
	string receives = PrunePeriods(secondary);
        if (accessToRelations.find(gives) == accessToRelations.end()) {
          accessToRelations[gives].push_back(receives);
        } else {
          list<string> list;
          list.push_back(receives);
          accessToRelations[gives] = list;
        }
	accessToRelations_r[receives] = gives;
	string num = marshallVal(table_num);
	table_num++;
	string sql;
	conn->execute(getCStr("DROP TABLE IF EXISTS "+table_name+num + " ;"));

	string indexes = "KEY " + receives + " ( " + receives + "), KEY " + gives + " ( " + gives + ")";
	if (receives != this->gives_pass) {

		sql = "CREATE TABLE " + table_name + num + " (" + gives + " " + PRINCTYPE + ", " + receives + " " + PRINCTYPE + ", symkey "TN_SYM_KEY", salt bigint, " + indexes + ");";
	} else {
		sql = "CREATE TABLE " + table_name + num + " (" + gives + " " + PRINCTYPE + ", " + receives + " " + PRINCTYPE + ", pubkey "TN_PK_KEY", " +indexes+");";
	}
	if (VERBOSE) {cerr << sql << "\n";}
	//fields_to_table[gives] = table_name + num;
	fields_to_table[receives] = table_name + num;


	if (!conn->execute(getCStr(sql))) {
		cerr << "sql raw query failed: " << sql << "\n";
		return -1;
	}
	return 0;
}

list<string> AccessManager::UnPrune(list<string> vals) {
	list<string> res = list<string>();

	for (list<string>::iterator it = vals.begin(); it != vals.end(); it++) {
		string aux = UnPrune(*it);
		res.push_back(aux);
	}
	return res;
}

list<string> AccessManager::hasAccess(string accessto) {
	list<string> res = list<string>();

	accessto = PrunePeriods(accessto);

	vector<string> equalVals = getEqualsFields(accessto);

	for (vector<string>::iterator it = equalVals.begin(); it != equalVals.end(); it++) {
		if(accessToRelations.find(*it) != accessToRelations.end()) {
			list<string> rets = UnPrune(accessToRelations[*it]);
			if (rets.size() > 0) {
				append(res, rets);
			}
		}
	}

	return res;
}

list<string> AccessManager::accessTo(string hasaccessto) {

	list<string> res = list<string>();

	hasaccessto = PrunePeriods(hasaccessto);

	if(accessToRelations_r.find(hasaccessto) != accessToRelations_r.end()) {
		res.push_back(UnPrune(accessToRelations_r[hasaccessto]));
	}

	if(access_map_r.find(hasaccessto) != access_map_r.end()) {
		hasaccessto = access_map_r[hasaccessto];
		if(accessToRelations_r.find(hasaccessto) != accessToRelations_r.end()) {
			res.push_back(UnPrune(accessToRelations_r[hasaccessto]));
		}
	}

	if(access_map.find(hasaccessto) != access_map.end()) {
		hasaccessto = access_map[hasaccessto];
		if(accessToRelations_r.find(hasaccessto) != accessToRelations_r.end()) {
			res.push_back(UnPrune(accessToRelations_r[hasaccessto]));
		}
	}

	return res;
}


list<string> AccessManager::inTableHasAccess(string accessto) {

	accessto = PrunePeriods(accessto);

	if(accessToRelations.find(accessto) != accessToRelations.end()) {
		return UnPrune(accessToRelations[accessto]);
	} else {
		return list<string>();
	}

}

string AccessManager::inTableAccessTo(string hasaccessto) {

	hasaccessto = PrunePeriods(hasaccessto);

	if(accessToRelations_r.find(hasaccessto) != accessToRelations_r.end()) {
		return UnPrune(accessToRelations_r[hasaccessto]);
	} else {
		return "";
	}

}


int AccessManager::addEquals(string field1, string field2) {
	if(VERBOSE) {
		cerr << "=> Record: " << field1 << " equals " << field2 << "\n";
	}
	field1 = PrunePeriods(field1);
	field2 = PrunePeriods(field2);
	//assume only one mapping FROM field1 and only one mapping TO field2
	if (access_map[field1].empty() && access_map_r[field2].empty()) {
	        access_map[field1] = field2;
		//cerr << "access_map " << field1 << "->" << field2 << endl;
		access_map_r[field2] = field1;
		//cerr << "access_map_r " << field2 << "->" << field1 << endl;
	}
	//else return error
	else {
	  cerr << "overwriting in an equals" << endl;
	  return -1;
	}
	return 0;
}


void AccessManager::addToMap(string field, string val, string username, unsigned char * key, int len) {
	if (VERBOSE) {
		cerr << "==> adding princ " << field << " val " << val << " uname " << username << " keylen " << len << " key "; myPrint(key, len); cerr<<"\n";
	}


	if (fast_keys.find(field) == fast_keys.end()) {
		fast_keys[field] = map<string, PrincipalMeta>();
	}

	if (fast_keys[field].find(val) == fast_keys[field].end()) {
		PrincipalMeta pm = PrincipalMeta();
		pm.usernames = list<string>();

		if (username.length() > 0) {
			pm.usernames.push_back(username);
		}

		pm.key = copy(key, len);
		pm.len = len;
		fast_keys[field][val] = pm;
	} else {
		PrincipalMeta pm = fast_keys[field][val];

		if (username.length() > 0) {
			addIfNotContained(username, pm.usernames);
		}

		if (VERBOSE) {
			cerr << "len in storage is "<< pm.len << "\n";
			cerr << "key is "; myPrint(key, AES_KEY_BYTES); cerr << " pm.key is "; myPrint(pm.key, AES_KEY_BYTES); cerr << "\n";
		}
		assert_s(isEqual(key, pm.key, len), "keys for same principal should be equal");
		fast_keys[field][val] = pm;
	}

}

bool AccessManager::getPrinc(string princ, string val, PrincipalMeta & pm) {
	if (fast_keys.find(princ) != fast_keys.end()) {
		if (fast_keys[princ].find(val) != fast_keys[princ].end()) {
			pm = fast_keys[princ][val];
			return true;
		}
	}
	return false;
}

int AccessManager::givesPsswd(string field) {

	if (PARSING) {
		return 0;
	}
	if(VERBOSE) {
	  cerr << "=> Record: " << field << " gives password" << endl;
	}
	field = PrunePeriods(field);
	//if there's already a field for this principle, returns error
	if (this->gives_pass != "")
	{
		return -1;
	}
	this->gives_pass = field;
	return 0;
}

int AccessManager::insertPsswd(string username, unsigned char * psswd) {

	if (PARSING) {
		return 0;
	}

	//check if username already has a password; return error if so
	if(VERBOSE) {
		cerr << "=> User " << username << " logs in with psswd ";
		myPrint(psswd, AES_KEY_BYTES);
		cerr << "\n";
	}
	//user is already logged on -- return error!
	if (password_map.find(username) != password_map.end()) {

			cerr << username << " is already logged in \n";
		return 1;
	}
	//else {
	//	password_map[username] = psswd;
	//}
	//either find from or insert into table for public keys
	// public_keys:
	// principle varchar(255) | sk TN_PK_KEY | salt bigint | pk TN_PK_KEY
	string sql = "SELECT * FROM public_keys WHERE principle='" + username + "'";
	DBResult *res;
	if (!conn->execute(getCStr(sql), res)) {
		cerr << "error executing " << getCStr(sql) << "\n";
		return -1;
	}
	vector<vector<string> > * res_table = conn->unpack(res);
	//if we already have a key for the user...
	if (res_table->size() > 1) {
		if (VERBOSE) {cerr << "We already have a key for " << username << endl;}
		//key for decryption is password
		unsigned char * dkey = psswd;
		unsigned int length;
		//get secret key and salt from public_keys, where it's encrypted with the user's password -- this is row 1 (because row 0 is field names) and column 1 (sk)
		unsigned char * ekey = unmarshallBinary(getCStr((*res_table)[1][1]),((*res_table)[1][1]).length(),length);
		uint64_t salt = unmarshallVal((*res_table)[1][2]);
		AES_KEY * aes = crypt_man->get_key_SEM(dkey);
		unsigned char * sec_key = crypt_man->decrypt_SEM(ekey,length,aes,salt);
		//save secret key in memory
		password_map[username] = sec_key;
		password_len[username] = length;
		string ssec_key = marshallBinary(sec_key,length);
		string ssalt = marshallVal(salt);
	}
	//if we don't have keys for this user, create them
	else {
		if (VERBOSE) {cerr << "We don't have a key for " << username << endl;}
		unsigned char * pass_key = psswd;
		int length;
		int length_pub;
		uint64_t salt = randomValue();
		AES_KEY * aes = crypt_man->get_key_SEM(pass_key);
		PKCS * rsa_pub_key;
		PKCS * rsa_sec_key;
	   // struct timeval starttime, endtime;
	    //gettimeofday(&starttime, NULL);
		crypt_man->generateKeys(rsa_pub_key, rsa_sec_key);
		//gettimeofday(&endtime, NULL);
		//cerr << "generate keys took " << timeInMSec(starttime, endtime) << "\n";
		//save secret key in memory
		unsigned char * pub_key = crypt_man->marshallKey(rsa_pub_key,true,length_pub);
		unsigned char * sec_key = crypt_man->marshallKey(rsa_sec_key,false,length);
		password_map[username] = sec_key;
		password_len[username] = length;
		//encrypt secret key with password
		string ssec_key = marshallBinary(sec_key,length);
		unsigned char * enc_sec_key = crypt_man->encrypt_SEM(sec_key, length, aes, salt);
		string senc_sec_key = marshallBinary(enc_sec_key,length);
		string spub_key = marshallBinary(pub_key,length_pub);
		string ssalt = marshallVal(salt);
		//unsigned char * tkey = crypt_man->decrypt_SEM(sec_key,
		sql = "INSERT INTO public_keys VALUES ('" + username + "'," + senc_sec_key + ", " + ssalt + ", " + spub_key + ");";
		if (!conn->execute(getCStr(sql))) {
			cerr << "SQL raw query failed\n";
			return -1;
		}
		return 0;
	}
	//for returning users:
	//  set up user_keys[username][field][value] = key for user to decrypt field = value
	//check key stuff...
	//set psswd to user's secret key
	psswd = password_map[username];
	map<string, map<string, unsigned char * > > field_to_valkey;
	map<string, map<string, int > > field_to_valkey_len;
	string field2 = this->gives_pass;
	list<string> value2;
	value2.push_back(username);
	map<string, unsigned char *> field_key;
	map<string, int> field_key_len;
	field_key[username] = psswd;
	field_key_len[username] = password_len[username];
	string field = this->gives_pass;
	while(field != "") {
		string table = fields_to_table[field2];
		if (VERBOSE) {
			cerr << field2 << endl;
			cerr << table << endl;
		}
		field = accessToRelations_r[field2];
		string sql = "SELECT * FROM " + table + " WHERE ";
		list<string>::iterator it;
		for(it = value2.begin(); it != value2.end(); it++) {
			sql += field2 + "='" + (*it) + "'";
			if ((*it) == value2.back()) {
				sql += ";";
			}
			else {
				sql += " OR ";
			}
		}
		value2.clear();
		//if(VERBOSE) {cerr << sql << endl;}
		DBResult * res;
		if (!conn->execute(getCStr(sql), res)) {
			cerr << "error executing " << getCStr(sql) << "\n";
			return -1;
		}
		vector<vector<string> > * vals = conn->unpack(res);
		int rows = vals->size() - 1;
		int cols;
		if (rows > 0) {
			cols = vals->at(0).size();
		} else {
			cols = 0;
		}
		bool ispk = false;
		if (cols == 3) {
			ispk = true;
		} else if ((cols != 4) and (!((cols == 0) && (rows <=0)))){
			//there should be 4 columns for symmetric key encryption, three for public, never any other number!
			cerr << "columns issue cols: " << cols << " rows:" << rows << "\n";
			return -1;
		}
		map<string, unsigned char *> value_to_key;
		map<string, int> value_to_key_len;
		string value;
		unsigned char * key;
		if (!ispk) {
			if (VERBOSE) {cerr << "symmetric key!" << endl;}
			for(int row = 0; row < rows; row++) {
				unsigned char * dkey = field_key[(*vals)[row+1][1]];
				value = (*vals)[row+1][0];
				unsigned int length;
				unsigned char * ekey = unmarshallBinary(getCStr((*vals)[row+1][2]),(*vals)[row+1][2].length(),length);
				uint64_t salt = unmarshallVal((*vals)[row+1][3]);
				AES_KEY * aes = crypt_man->get_key_SEM(dkey);
				key = crypt_man->decrypt_SEM(ekey,AES_KEY_BYTES,aes,salt);
				value_to_key[value] = key;
				value_to_key_len[value] = AES_KEY_BYTES;
				value2.push_back(value);
			}
		} else {
			if(VERBOSE) {cerr << "public key!" << endl;}
			for(int row = 0; row < rows; row++) {
				unsigned int length;
				//unsigned char * sec_key = field_key[(*vals)[row+1][1]];
				//int len = field_key_len[(*vals)[row+1][1]];
				unsigned char * sec_key = password_map[username];
				int len = password_len[username];
				PKCS * pk_sec_key = crypt_man->unmarshallKey(sec_key,len,false);
				//if (pk_sec_key == NULL) {cerr << "x_x" << endl;}
				value = (*vals)[row+1][0];
				unsigned char * enc_key = unmarshallBinary(getCStr((*vals)[row+1][2]),(*vals)[row+1][2].length(),length);
				unsigned char * key = crypt_man->decrypt(pk_sec_key, enc_key, length, len);
				value_to_key[value] = key;
				value_to_key_len[value] = len;
				value2.push_back(value);
			}
		}
		field_to_valkey[field] = value_to_key;
		field_to_valkey_len[field] = value_to_key_len;
		if (VERBOSE) {cerr << "field_to_valkey[" << field << "]" << endl;}
		if(!access_map[field].empty()) {
		  field_to_valkey[access_map[field]] = value_to_key;
		  field_to_valkey_len[access_map[field]] = value_to_key_len;
		  if (VERBOSE) {cerr << "f: field_to_valkey[" << access_map[field] << "]" << endl;}
		}
		if(!access_map_r[field].empty()) {
		  field_to_valkey[access_map_r[field]] = value_to_key;
		  field_to_valkey_len[access_map_r[field]] = value_to_key_len;
		  if (VERBOSE) { cerr << "r: field_to_valkey[" << access_map_r[field] << "]" << endl;}
		}
		//update
		field_key = value_to_key;
		field2 = access_map_r[field];
		if (VERBOSE) {cerr << field << " " << field2 << endl;}
		if (accessToRelations_r.find(field2) != accessToRelations_r.end() && !value2.empty()) {
			field = accessToRelations_r[field2];
		}
		else {
			break;
		}
	}

	//ADD KEYS IN FAST_KEYS AS WELL
	map<string, map<string, unsigned char*> >::iterator vit = field_to_valkey.begin();
	map<string, map<string, int> >::iterator lit = field_to_valkey_len.begin();

	for (; vit != field_to_valkey.end(); vit++, lit++) {
		string field = vit->first;
		map<string, unsigned char *> valkey = vit->second;
		map<string, int> vallen = lit->second;
		map<string, unsigned char *>::iterator vitt = valkey.begin();
		map<string, int>::iterator litt = vallen.begin();

		for (; vitt != valkey.end();vitt++, litt++) {
			string val = vitt->first;
			unsigned char * key = vitt->second;
			int len = litt->second;
			addToMap(field, val, username, key, len);
			user_keys[username][field][val] = true;
		}

	}

	return 0;
}

bool AccessManager::removeFromMap(string princ, string val, string username) {
	if (fast_keys.find(princ) == fast_keys.end()) {
		return false;
	}
	if (fast_keys[princ].find(val) == fast_keys[princ].end()) {
		return false;
	}

	if (contains(username, fast_keys[princ][val].usernames)) {
		fast_keys[princ][val].usernames.remove(username);
		if (fast_keys[princ][val].usernames.size() == 0) {
			//remove this entry
			fast_keys[princ].erase(val);
		}
		return true;
	}

	return false;
}

//void myprint(map<>)

int AccessManager::deletePsswd(string username) {


	if(VERBOSE)
		cerr << "=> User " << username << " logs out. \n";
	if (password_map.find(username) == password_map.end()) {
		return 1;
	}
	password_map.erase(username);

	//delete appropriate part of fast_keys
	if (user_keys.find(username) != user_keys.end()) {
		map<string, map<string, bool> >::iterator it = user_keys[username].begin();
		map<string, map<string, bool> >::iterator itend = user_keys[username].end();

		for (; it!=itend ; it++) {
			string princ = it->first;
			map<string, bool>::iterator itt = it->second.begin();
			map<string, bool>::iterator ittend = it->second.end();

			for ( ; itt!=ittend ; itt++) {
				string val = itt->first;
				removeFromMap(princ, val, username);
			}
		}

	}

	user_keys.erase(username);

	//cerr << "all keys now on the machine are: \n";
	//myprint(user_keys);
	//myprint(fast_keys);


	if (VERBOSE) { cerr << "done with logging out\n";}
	return 0;
}

//returns true if the first value in res  is greater than val
bool isLarger(ResType * res, unsigned int val) {
	assert_s(res->size() == 2, "given res to isLarger() has less than 2 rows ");
	return (unmarshallVal(res->at(1).at(0)) > val);
}

bool AccessManager::princInstanceInTables(string princ, string value) {

	if (VERBOSE) {cerr << "in princInstanceTables for " << princ << "\n";}

	list<string> haveAccess = hasAccess(UnPrune(princ));

	assert_s(haveAccess.size() > 0, "asking instance for field that is not internal principal");



	for (list<string>::iterator it = haveAccess.begin(); it != haveAccess.end(); it++) {

		string currHasAccess = PrunePeriods(*it);
		string table = fields_to_table[currHasAccess];

		if (table.length() == 0) {
			if (VERBOSE) {
				cerr << "table is empty for " << currHasAccess << "\n";
				cerr << "here is what fields_to_table contains \n";

				for (map<string, string>::iterator it = fields_to_table.begin(); it != fields_to_table.end(); it++) {
					cerr << it->first << " " << it->second << "\n";
				}
				cerr << "printed\n";
			}
		}

		string sql = "SELECT count(*) FROM " + table + " WHERE " + accessToRelations_r[currHasAccess] +  " =  '" + value + "' ;";

		if (VERBOSE) {cerr << sql << "\n";}

		DBResult * dbres;
		bool res = conn->execute(getCStr(sql), dbres);
		assert_s(res, "issue with sql query: " + sql);

		if (isLarger(conn->unpack(dbres), 0)) {
			if (VERBOSE) {cerr << " principal instance found\n";}
			return true;
		}
	}

	return false;

}
string AccessManager::equalsHasKey(string princ, string val) {

	vector<string> eq = getEqualsFields(princ);

	for (vector<string>::iterator it = eq.begin(); it!=eq.end(); it++) {
		PrincipalMeta pm;
		if (getPrinc(*it, val, pm)) {
			return *it;
		}
	}

	return "";

}
int AccessManager::insert(list<string> fields, list<string> ids) {


	if (PARSING) {
		return 0;
	}
	if (VERBOSE) {
		cerr << "==> insert <" << fields.front() << "> <" << fields.back() << "> <" << ids.front() << "> <" << ids.back() << "> \n";
	}
	//assuming for now fields only has 2 elements
	fields.front() = PrunePeriods(fields.front());//accessto
	fields.back() = PrunePeriods(fields.back());//hasaccess

	if (fields.size() != ids.size()) {
		cerr << "incorrect insertion values\n";
		return -1;
	}

	string table = fields_to_table[fields.back()];
	if (table == "") {
		cerr << "fields_to_table empty for " << fields.front() << "\n " ;
		return -1;
	}

	//CHECK IF INSERT RELATION ALREADY EXISTS

	//see if this key is already in the table and we can read it!
	string sql = "SELECT count(*) FROM " + table + " WHERE " + fields.front() + "='" + ids.front() + "' AND " + fields.back() + "='" + ids.back() + "';";
	DBResult * dbres;
	if (!conn->execute(getCStr(sql), dbres)) {
	  cerr << "SQL error" << endl;
	  return -1;
	}
	if (isLarger(conn->unpack(dbres), 0)) {
		if (VERBOSE) {cerr << "relation already exists\n";}
		return 0;
	}

	unsigned char * key;
	uint64_t salt = randomValue();

	// OBTAIN KEY

	//check if key is in table at all (only use first field)
	//  if so, decrypt key, re-encrypt for this uid (if possible -- if not, generate a new key and update)
	key =  this->internalGetKey(fields.front(),ids.front());
	if (!key) {

		if (VERBOSE) {cerr << "==> principal instance found in tables \n";}
		if (princInstanceInTables(fields.front(), ids.front())) {
			cerr << "Key is inaccessible.  Is the admin online?" << endl;
			return -1;
		}

		else {
			if (VERBOSE) {cerr << "==> principal instance " << fields.front() << " " << ids.front() << " not found in tables \n";}
			//maybe this is an orphan principal
			string eqfield = equalsHasKey(fields.front(), ids.front());

			if (eqfield.length() > 0) {
				PrincipalMeta pm;
				assert_s(getPrinc(eqfield, ids.front(), pm), "should have existed in fast_keys");
				//we found the data in fast_keys, but it was not in the tables, so it must be an orphan

				key = pm.key;
				if (VERBOSE) {cerr << "==> using orphan key " <<  fields.front() << " " << ids.front() << " "; myPrint(key, AES_KEY_BYTES); cerr << "\n";}
				//it is not orphan any more
				//TODO: all of them should be false here


			} else {
				//this is a new principal instance and we generate a new key
				key = randomBytes(AES_KEY_BYTES);
				if (VERBOSE) {cerr << "==> generate new key for " << fields.front() << " " << ids.front() << " "; myPrint(key, AES_KEY_BYTES); cerr << "\n";}
			}
		}
	}

	//put key in user_keys
	//if this field gives password, put the key for the principal it has access to to be available by this user
	//this user should also have the keys of the principals equal to that one
	if(fields.back() == this->gives_pass) {
		user_keys[ids.back()][fields.front()][ids.front()] = true;
		string username = ids.back();
		addToMap(fields.front(), ids.front(), username, key, AES_KEY_BYTES);
		if(!access_map[fields.front()].empty()) {
			user_keys[ids.back()][access_map[fields.front()]][ids.front()] = true;
			addToMap(access_map[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		}
		if(!access_map_r[fields.front()].empty()) {
			user_keys[ids.back()][access_map_r[fields.front()]][ids.front()] = true;
			addToMap(access_map_r[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		}
	}

	//now it is not a username, though it can be
	//(gid, uid) : (3,5)
	//go through all users who have access to "hasaccess" and add them the key for accessto and also this key to all equals to it
	map<string,map<string,map<string, bool> > >::iterator it;
	for(it = user_keys.begin(); it != user_keys.end(); it++) {
		string username = (*it).first;
		string field = fields.back();
		if (VERBOSE) {cerr << field << endl;}
		//insert key as anything this field is equal to
		//TODO: make this change in remove
		if(user_keys[username][field].find(ids.back()) != user_keys[username][field].end()) {
			if (VERBOSE) {cerr << "user_keys[" << username << "][" << fields.front() << "][" << ids.front() << "]" << endl;}
		  user_keys[username][fields.front()][ids.front()] = true;
		  addToMap(fields.front(), ids.front(), username, key, AES_KEY_BYTES);
		  if(!access_map[fields.front()].empty()) {
			  if (VERBOSE) { cerr << "user_keys[" << username << "][" << access_map[fields.front()] << "][" << ids.front() << "]" << endl;}
		    user_keys[username][access_map[fields.front()]][ids.front()] = true;
		    addToMap(access_map[fields.front()], ids.front(), username,  key, AES_KEY_BYTES);
		  }
		  if(!access_map_r[fields.front()].empty()) {
			  if (VERBOSE) {cerr << "user_keys[" << username << "][" << access_map_r[fields.front()] << "][" << ids.front() << "]" << endl;}
		    user_keys[username][access_map_r[fields.front()]][ids.front()] = true;
		    addToMap(access_map_r[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		  }
		}
		field = access_map[fields.back()];	
		if(user_keys[username][field].find(ids.back()) != user_keys[username][field].end()) {
		  user_keys[username][fields.front()][ids.front()] = true;
		  addToMap(fields.front(), ids.front(), username, key, AES_KEY_BYTES);
		  if(!access_map[fields.front()].empty()) {
		    user_keys[username][access_map[fields.front()]][ids.front()] = true;
		    addToMap(access_map[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		  }
		  if(!access_map_r[fields.front()].empty()) {
		    user_keys[username][access_map_r[fields.front()]][ids.front()] = true;
		    addToMap(access_map_r[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		  }
		}
		field = access_map_r[fields.back()];	
		if(user_keys[username][field].find(ids.back()) != user_keys[username][field].end()) {
		  user_keys[username][fields.front()][ids.front()] = true;
		  addToMap(fields.front(), ids.front(), username, key, AES_KEY_BYTES);
		  if(!access_map[fields.front()].empty()) {
		    user_keys[username][access_map[fields.front()]][ids.front()] = true;
		    addToMap(access_map[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		  }
		  if(!access_map_r[fields.front()].empty()) {
		    user_keys[username][access_map_r[fields.front()]][ids.front()] = true;
		    addToMap(access_map_r[fields.front()], ids.front(), username, key, AES_KEY_BYTES);
		  }
		}
	}

	//if second field is not username, get key for this second principal, insert the key into tables
	if (fields.back() != this->gives_pass) {
	        unsigned char *user_key = internalGetKey(fields.back(),ids.back());
		AES_KEY * aes = crypt_man->get_key_SEM(user_key);
		unsigned char * ekey = crypt_man->encrypt_SEM(key, AES_KEY_BYTES, aes, salt);
		string skey = marshallBinary(ekey,AES_KEY_BYTES);
		string ssalt = marshallVal(salt);
		sql = "INSERT INTO " + table + " VALUES ('" + ids.front() + "','" + ids.back() + "'," + skey + ", " + ssalt +");";
	}
	else {
		//user_key = password_map[ids.back()];
		unsigned int length;
		if(password_map.find(ids.back()) == password_map.end()) {
		  cerr << "cannot find password for " << ids.back() << "\n";
		  return -1;
		}
		unsigned char * pub_key = getPublicKey(ids.back(),length);
		PKCS * pk_pub_key = crypt_man->unmarshallKey(pub_key,length,true);

		if (pk_pub_key == NULL) {
			cerr << "pub key is null \n";
			return -1;
		}

		int res_length;
		unsigned char * enc_pub_key = crypt_man->encrypt(pk_pub_key,key,AES_KEY_BYTES,res_length);
		string senc_pub_key = marshallBinary(enc_pub_key,res_length);
		//update table to reflect new key
		sql = "INSERT INTO " + table + " VALUES ('" + ids.front() + "','" + ids.back() + "'," + senc_pub_key + ");";
	}

	//if (VERBOSE) {cerr << sql << "\n";}
	if (!conn->execute(getCStr(sql))) {
		cerr << "raw query " << sql << " failed \n";
		return -1;
	}


	return 0;
}

int AccessManager::remove(list<string> fields, list<string> ids) {
	assert_s(false, "remove needs revision");
  return -1;
/*        if(VERBOSE) {
	  cerr << "==> remove <" << fields.front() << "> <" << fields.back() << "> <" << ids.front() << "> <" << ids.back() << ">\n";
	}
	fields.front() = PrunePeriods(fields.front());
	fields.back() = PrunePeriods(fields.back());


	//table first field is in
	string table = fields_to_table[fields.back()];
	if (table == "") {
	  return -1;
	}
	string sql = "DELETE FROM " + table + " WHERE " + fields.front() + "='" + ids.front() + "' AND " + fields.back() + "='" + ids.back() + "';";
	//if(VERBOSE) {cerr << sql << endl;}
	DBResult * res;
	//if key is not in table, return nothing
	if (!conn->execute(getCStr(sql),res)) {
		cerr << "raw query failed: " << sql << "\n";
		return -1;
	}
	//check number of rows affected is not 0...
	if (mysql_affected_rows(conn->conn) == 0) {
			cerr << "mysql affected rows 0 \n";
	        return -1;
	}
	//if this is a username to uid type key, delete
	if(fields.back() == this->gives_pass) {
	        user_keys[ids.back()][fields.front()].erase(ids.front());
	}
	//delete all instances of user_keys[*][first field][first id]
	//map<string,map<string,map<string,unsigned char *> > >::iterator it;
	unsigned char * key = getKey(fields.back(),ids.back());
	map<string,map<string,map<string,unsigned char *> > >::iterator it;
	cerr << "the key..." << endl;
	for(it = user_keys.begin(); it != user_keys.end(); it++) {
	        string username = (*it).first;
		cerr << username << endl;
		//fields.back()
		if(user_keys[username].find(fields.back()) != user_keys[username].end()) {
		  cerr << "found " << fields.back() << endl;
		  if(user_keys[username][fields.back()].find(ids.back()) != user_keys[username][access_map[fields.back()]].end()) {
		    cerr << "found " << ids.back() << endl;
		    if(user_keys[username][fields.back()][ids.back()] == key) {
		      if((user_keys[username].find(fields.front()) != user_keys[username].end()) && (user_keys[username][fields.front()].find(ids.front()) != user_keys[username][fields.front()].end())) {
			cerr << "removing user_keys[" << username << "][" << fields.front() << "][" << ids.front() << "]" << endl;
			user_keys[username][fields.front()].erase(ids.front());
		      }
		      if((user_keys[username].find(access_map[fields.front()]) != user_keys[username].end()) && (user_keys[username][access_map[fields.front()]].find(ids.front()) != user_keys[username][access_map[fields.front()]].end())) {
			user_keys[username][access_map[fields.front()]].erase(ids.front());
		      }
		      if((user_keys[username].find(access_map_r[fields.front()]) != user_keys[username].end()) && (user_keys[username][access_map_r[fields.front()]].find(ids.front()) != user_keys[username][access_map_r[fields.front()]].end())) {
			user_keys[username][access_map_r[fields.front()]].erase(ids.front());
		      }
		    }
		  }
		}
		//access_map[fields.back()]
		if(user_keys[username].find(access_map[fields.back()]) != user_keys[username].end()) {
		  if(user_keys[username][access_map[fields.back()]].find(ids.back()) != user_keys[username][access_map[fields.back()]].end()) {
		    if(user_keys[username][access_map[fields.back()]][ids.back()] == key) {
		      if((user_keys[username].find(fields.front()) != user_keys[username].end()) && (user_keys[username][fields.front()].find(ids.front()) != user_keys[username][fields.front()].end())) {
			user_keys[username][fields.front()].erase(ids.front());
		      }
		      if((user_keys[username].find(access_map[fields.front()]) != user_keys[username].end()) && (user_keys[username][access_map[fields.front()]].find(ids.front()) != user_keys[username][access_map[fields.front()]].end())) {
			user_keys[username][access_map[fields.front()]].erase(ids.front());
		      }
		      if((user_keys[username].find(access_map_r[fields.front()]) != user_keys[username].end()) && (user_keys[username][access_map_r[fields.front()]].find(ids.front()) != user_keys[username][access_map_r[fields.front()]].end())) {
			user_keys[username][access_map_r[fields.front()]].erase(ids.front());
		      }
		    }
		  }
		}
		//access_map_r[fields.back()]
		if(user_keys[username].find(access_map_r[fields.back()]) != user_keys[username].end()) {
		  if(user_keys[username][access_map_r[fields.back()]].find(ids.back()) != user_keys[username][access_map[fields.back()]].end()) {
		    if(user_keys[username][access_map_r[fields.back()]][ids.back()] == key) {
		      if((user_keys[username].find(fields.front()) != user_keys[username].end()) && (user_keys[username][fields.front()].find(ids.front()) != user_keys[username][fields.front()].end())) {
			user_keys[username][fields.front()].erase(ids.front());
		      }
		      if((user_keys[username].find(access_map[fields.front()]) != user_keys[username].end()) && (user_keys[username][access_map[fields.front()]].find(ids.front()) != user_keys[username][access_map[fields.front()]].end())) {
			user_keys[username][access_map[fields.front()]].erase(ids.front());
		      }
		      if((user_keys[username].find(access_map_r[fields.front()]) != user_keys[username].end()) && (user_keys[username][access_map_r[fields.front()]].find(ids.front()) != user_keys[username][access_map_r[fields.front()]].end())) {
			user_keys[username][access_map_r[fields.front()]].erase(ids.front());
		      }
		    }
		  }
		}
	}
	return 0;
	*/
}

/*Testing Backdoor*/
void AccessManager::savekey(string field, string value) {
	this->savefield = PrunePeriods(field);
	this->savevalue = PrunePeriods(value);
}


unsigned char * AccessManager::findKey(string field, string val) {
	if (fast_keys.find(field) != fast_keys.end()) {
		if (fast_keys[field].find(val) != fast_keys[field].end()) {
			return fast_keys[field][val].key;
		}
	}
	return NULL;
}
vector<string> AccessManager::getEqualsFields(string field) {
	map<string, bool > visited;
	vector<string> res;
	res.push_back(field);
	visited[field] = true;

	//do a breadth first search
	int start = 0;
	int end = 0;

	while (start <= end) {
		string currfield = res[start];

		if (access_map.find(currfield) != access_map.end()) {
			string equalField = access_map[currfield];
			if (visited.find(equalField) == visited.end()) {
				visited[equalField] = true;
				end++;
				res.push_back(equalField);

			}
		}
		if (access_map_r.find(currfield) != access_map_r.end()) {
			string equalField = access_map_r[currfield];
			if (visited.find(equalField) == visited.end()) {
				visited[equalField] = true;
				end++;
				res.push_back(equalField);
			}
		}
		start++;
	}

	return res;

}

bool AccessManager::isOrphan(string princ, string value) {

	return !princInstanceInTables(princ, value);

}

unsigned char * AccessManager::getKey(string encryptedForField, string encryptedForValue) {

	if (PARSING) {
		return NULL;
	}
	if (VERBOSE) {
		cerr << "==>getKey " << encryptedForField << " = " << encryptedForValue << "\n";
	}
	return internalGetKey(PrunePeriods(encryptedForField), encryptedForValue);

}
unsigned char * AccessManager::internalGetKey(string field, string encryptedForValue) {


	if(VERBOSE) {
		cerr << "=>getKey " << field << " = " << encryptedForValue << "\n";
	}

	vector<string> equalsList = getEqualsFields(field);

	for (vector<string>::iterator it = equalsList.begin(); it!=equalsList.end(); it++) {
		unsigned char * key = findKey(*it, encryptedForValue);
		if (key!=NULL) {
			if (VERBOSE) {cerr << "==> key is "; myPrint(key, AES_KEY_BYTES); cerr << "\n";}
			return key;
		}
	}

	//key not found among principals accessible by online users
	//check if this is an orphan -- a principal not defined before

	//if (!isOrphan(field, encryptedForValue)) {
	//	cerr << "key exists, but you cannot access it\n";
	//	return NULL;
	//}

	if (VERBOSE) {cerr << "assuming you are orphan\n";}

	//orphan principal
	unsigned char * key = randomBytes(AES_KEY_BYTES);

	if (VERBOSE) {cerr << "==> orphan " << field << " " << encryptedForValue << " key "; myPrint(key, AES_KEY_BYTES); cerr << "\n";}

	if (VERBOSE) {cerr << "==> key is "; myPrint(key, AES_KEY_BYTES); cerr << "\n";}

	addToMap(field, encryptedForValue, "", key, AES_KEY_BYTES);

	return key;
}

unsigned char * AccessManager::getPublicKey(string username, unsigned int &length) {
  	string sql = "SELECT * FROM public_keys WHERE principle='" + username + "'";
	DBResult * res;
	if (!conn->execute(getCStr(sql),res)) {
		cerr << "nu public key\n";
		return NULL;
	}
	vector<vector<string> > * res_table = conn->unpack(res);
	if (res_table->size() > 1) {
	  unsigned int len;
	  unsigned char * pub_key = unmarshallBinary(getCStr((*res_table)[1][3]),((*res_table)[1][3]).length(),len);
	  length = len;
	  return pub_key;
	}
	return NULL;
}

string AccessManager::PrunePeriods(string input) {

	assert_s(input.find(".") != string::npos, "input to pruneperiods does not have '.' separator");

	int nodigits = input.find(".");

	string repr = marshallVal(nodigits, NODIGITS);
	assert_s(repr.length() <= NODIGITS, "given fieldname is longer than max allowed by pruning ");

	string result = repr + input.substr(0, nodigits) + input.substr(nodigits+1, input.length()-1-nodigits);

	return result;
}

string AccessManager::UnPrune(string input) {
  unsigned int digits = 0;

  for (int i = 0; i < NODIGITS; i++) {
	  digits = digits*10 + (int)(input[i]-'0');
  }

  unsigned int fieldlen = input.length() - NODIGITS -digits;

  string res = input.substr(NODIGITS, digits) + "." + input.substr(NODIGITS+digits, fieldlen);


  return res;
}

void AccessManager::finish() {
	map<string, string>::iterator it =  fields_to_table.begin();

	while (it != fields_to_table.end()) {	        
	        string q = "DROP TABLE IF EXISTS " + it->second + ";";
		if (!it->second.empty()) {
		  conn->execute(getCStr(q));
		}
		it++;
	}

	fields_to_table.clear();

	conn->finish();

	access_map.clear();
	access_map_r.clear();
	password_map.clear();
	fast_keys.clear();
}
AccessManager::~AccessManager() {
	finish();
}

