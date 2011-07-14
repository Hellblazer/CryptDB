/**
 *  This is the crypto manager.
 */

#include <stdlib.h>

#include "CryptoManager.h"


/*
//either provide a level key or provide a master key and the name of the field
void EDBClient::encrypt(SECLEVEL seclevel, string plaintext, uint64_t salt, unsigned char * levelkey, unsigned char * mkey, string fieldname, string & ciphertext) {
	switch seclevel {
	case SEM: {}
	case DET: {}
	case OPE: {}
	case DETJOIN: {}
	case
	}
}
void EDBClient::decrypt(SECLEVEL seclevel, string & plaintext, uint64_t salt, unsigned char * levelkey, unsigned char * mkey, string fieldname, string ciphertext) {

}
 */
// TODO: simplify CryptoManager using a function taking from level to level for a type of data using union for answers or inputs
// TODO: optimizations for CryptAPP, HOM especially; for each user, for each field, keep the keys in the right format already and just load them rather than recompute

ZZ Paillier_L(const ZZ & u, const ZZ & n) {
	return (u - 1) / n;
}

ZZ LCM(const ZZ & a, const ZZ & b) {
	return (a * b) / GCD(a, b);
}

AES_KEY * CryptoManager::getmkey() {
	return masterKey;
}

CryptoManager::CryptoManager(unsigned char * masterKey) {

	VERBOSE = VERBOSE_G;
	this->masterKey = new AES_KEY();

	this->masterKeyBytes = masterKey;

	AES_set_encrypt_key(masterKey, AES_KEY_SIZE, this->masterKey);

	RAND_seed(masterKey, MASTER_KEY_SIZE);

	SetSeed(ZZFromBytes(masterKey, MASTER_KEY_SIZE));

	useEncTables = false;

	//setup Paillier encryption
	ZZ p, q;

	p = RandomPrime_ZZ(Paillier_len_bits/4);
	q = RandomPrime_ZZ(Paillier_len_bits/4);

	Paillier_n = p * q ;
	Paillier_n2 = Paillier_n * Paillier_n;

	Paillier_lambda = LCM(p-1, q-1);

	//generate g

	do {

		Paillier_g = RandomLen_ZZ(Paillier_len_bits) % Paillier_n2;

	} while (GCD(Paillier_L(PowerMod(Paillier_g, Paillier_lambda, Paillier_n2), Paillier_n), Paillier_n) != to_ZZ(1));


	Paillier_dec_denom = InvMod(Paillier_L(PowerMod(Paillier_g,  Paillier_lambda, Paillier_n2),
			Paillier_n),
			Paillier_n);



}

SECLEVEL highestEq(SECLEVEL sl) {
	if (sl == SEMANTIC_DET) {
		return DET;
	} else {
		return sl;
	}
}

onion getOnion(SECLEVEL l1) {
	switch (l1) {
	case PLAIN_DET: {return oDET;}
	case DETJOIN: {return oDET;}
	case DET: {return oDET;}
	case SEMANTIC_DET: {return oDET;}
	case PLAIN_OPE: {return oOPE;}
	case OPEJOIN: {return oOPE;}
	case OPESELF: {return oOPE;}
	case SEMANTIC_OPE: {return oOPE;}
	case PLAIN_AGG: {return oAGG;}
	case SEMANTIC_AGG: {return oAGG;}
	case PLAIN: {return oNONE;}
	default: {return oINVALID;}
	}
	return oINVALID;
}

SECLEVEL decreaseLevel(SECLEVEL l, fieldType ft,  onion o) {
	switch (o){
	case oDET: {
		switch (l) {
		case SEMANTIC_DET: {return DET;}
		case DET: {
			if (ft == TYPE_TEXT) {
				return PLAIN_DET;
			} else {
				return DETJOIN;
			}
			}
		case DETJOIN: {return PLAIN_DET;}
		default: {
			assert_s(false, "cannot decrease level");
			return INVALID;
		}
		}
    }
	case oOPE: {
		switch (l) {
		case SEMANTIC_OPE: {return OPESELF;}
		case OPESELF: {return OPEJOIN;}
		case OPEJOIN: {return PLAIN_OPE;}
		default: {
			assert_s(false, "cannot decrease level");
			return INVALID;
		}
		}
	}
	case oAGG: {
		switch (l) {
		case SEMANTIC_AGG: {return PLAIN_AGG;}
		default: {
			assert_s(false, "cannot decrease level");
			return INVALID;
		}
		}
	}
	default: {
		assert_s(false, "cannot decrease level");
		return INVALID;
	}
	}

}
SECLEVEL increaseLevel(SECLEVEL l, fieldType ft, onion o) {
	switch (o){
	case oDET: {
		switch (l) {
		case DET: {return SEMANTIC_DET;}
		case DETJOIN: {return DET;}
		case PLAIN_DET: {
			if (ft == TYPE_TEXT) {
				return DET;
			} else {
				return DETJOIN;
			}
		}
		default: {
			assert_s(false, "cannot increase level");
			return INVALID;
		}
		}
    }
	case oOPE: {
		switch (l) {
		case OPESELF: {return SEMANTIC_OPE;}
		case OPEJOIN: {return OPESELF;}
		case PLAIN_OPE: {return OPEJOIN;}
		default: {
					assert_s(false, "cannot increase level");
					return INVALID;
				}
		}
	}
	case oAGG: {
		switch (l) {
		case PLAIN_AGG: {return SEMANTIC_AGG;}
		default: {
					assert_s(false, "cannot increase level");
					return INVALID;
				}
		}
	}
	default: {
		assert_s(false, "cannot increase level");
		return INVALID;
	}
	}

}



//////////////////////////////////////////////////////////////////


//TODO: optimization: crypt can take in an array of elements to decrypt as opposed to just one field
// when we want to decrypt many items from a column, in this way, we do not need to construct the key every time
string CryptoManager::crypt(AES_KEY * mkey, string data, fieldType ft, string fullfieldname,
		SECLEVEL fromlevel, SECLEVEL tolevel, uint64_t salt) {

	//cerr << "+ crypt: salt " << salt << " data " << data << " fullfieldname " << fullfieldname << " fromlevel " << fromlevel << " to level" << tolevel << "\n";
	onion o = getOnion(fromlevel);

	myassert((o != oINVALID) && (o == getOnion(tolevel)), "levels for crypt are not on the same onion");

	int comp = fromlevel - tolevel;

	if (comp == 0) {
		//do nothing
		return data;
	}

	if (comp > 0) {
		//need to decrypt

		switch (ft) {
		case TYPE_INTEGER: {

			switch (o) {
			case oDET: {
				uint64_t val = unmarshallVal(data);
				if (fromlevel == SEMANTIC_DET) {
					AES_KEY * key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
					val = decrypt_SEM(val, key, salt);
					fromlevel  = decreaseLevel(fromlevel, ft, oDET);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				if (fromlevel == DET) {
					AES_KEY * key = get_key_DET(getKey(mkey, fullfieldname, fromlevel));
					val = decrypt_DET(val, key);
					fromlevel = decreaseLevel(fromlevel, ft, oDET);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				if (fromlevel == DETJOIN) {
					AES_KEY * key = get_key_DET(getKey(mkey, "join", fromlevel));
					val = decrypt_DET(val, key);
					fromlevel = decreaseLevel(fromlevel, ft, oDET);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				assert_s(false, "nothing lower than plain");

				return "";
			}
			case oOPE: {
				uint64_t val = unmarshallVal(data);
				if (fromlevel == SEMANTIC_OPE) {
					AES_KEY * key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
					val = decrypt_SEM(val, key, salt);
					fromlevel  = decreaseLevel(fromlevel, ft, oOPE);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				if (fromlevel == OPESELF) {
					OPE * key = get_key_OPE(getKey(mkey, fullfieldname, fromlevel));
					val = decrypt_OPE(val, key);
					fromlevel = decreaseLevel(fromlevel, ft, oOPE);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				if (fromlevel == OPEJOIN) {
					fromlevel = decreaseLevel(fromlevel, ft, oOPE);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				assert_s(false, "nothing lower than plain ope");

				return "";
			}
			case oAGG: {
				unsigned int newlen = 0;
				unsigned char * uval = unmarshallBinary(getCStr(data), data.length(), newlen);
				if (fromlevel == SEMANTIC_AGG) {
					uint64_t val = decrypt_Paillier(uval);
					fromlevel  = decreaseLevel(fromlevel, ft, oAGG);
					if (fromlevel == tolevel) {
						return marshallVal(val);
					}
				}

				assert_s(false, "nothing lower than plain agg");

				return "";
			}
			default: {
				assert_s(false, "no other onions possible\n");
				return "";
			}
			}
			assert_s(false, "no other onions possible\n");
			return "";
		}
		case TYPE_TEXT:{

			switch (o) {
			case oDET: {
				unsigned int newlen = 0;
				unsigned char * val = unmarshallBinary(getCStr(data), data.length(), newlen);
				if (fromlevel == SEMANTIC_DET) {
					AES_KEY * key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
					val = decrypt_SEM(val, newlen, key, salt);
					fromlevel  = decreaseLevel(fromlevel, ft, oDET);
					if (fromlevel == tolevel) {
						return marshallBinary(val,newlen);
					}
				}

				if (fromlevel == DET) {
					AES_KEY * key = get_key_DET(getKey(mkey, fullfieldname, fromlevel));
					string res  = decrypt_DET_wrapper(val, newlen, key);
					fromlevel = decreaseLevel(fromlevel, ft, oDET);
					if (fromlevel == tolevel) {
						return res;
					}
				}

				if (fromlevel == DETJOIN) {
					assert_s(false, "no join for text \n");
					return "";
				}

				assert_s(false, "nothing lower than plain");

				return "";
			}
			case oOPE: {
				return "5";
				//not yet implemented
			}
			default: {
				myassert(false, "no valid onion in text \n");
				return "";
			}

			}
			myassert(false, "no valid onion in text \n");
			return "";
		}
		default: {
			myassert(false, "no other types possible \n");
			return "";
		}
		}


	}

	//ENCRYPT
	myassert(comp < 0, "problem with crypt: comp should be > 0");

	switch (ft) {
	case TYPE_INTEGER: {

		switch (o) {
		case oDET: {
			uint64_t val = unmarshallVal(data);

			if (fromlevel == PLAIN_DET) {
				fromlevel = increaseLevel(fromlevel, ft, oDET);
				AES_KEY * key = get_key_DET(getKey(mkey, "join", fromlevel));
				val = encrypt_DET(val, key);
				if (fromlevel == tolevel) {
					return marshallVal(val);
				}
			}


			if (fromlevel == DETJOIN) {
				fromlevel = increaseLevel(fromlevel, ft, oDET);
				AES_KEY * key = get_key_DET(getKey(mkey, fullfieldname, fromlevel));
				val = encrypt_DET(val, key);
				if (fromlevel == tolevel) {
					return marshallVal(val);
				}
			}

			if (fromlevel == DET) {
				fromlevel  = increaseLevel(fromlevel, ft, oDET);
				AES_KEY * key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
				val = encrypt_SEM(val, key, salt);
				if (fromlevel == tolevel) {
					return marshallVal(val);
				}
			}


			assert_s(false, "nothing higher than SEM");


			return "";
		}
		case oOPE: {
			uint64_t val = unmarshallVal(data);

			if (fromlevel == PLAIN_OPE) {
				fromlevel = increaseLevel(fromlevel, ft, oOPE);
				if (fromlevel == tolevel) {
					return marshallVal(val);
				}
			}

			if (fromlevel == OPEJOIN) {
				fromlevel = increaseLevel(fromlevel, ft, oOPE);
				OPE * key = get_key_OPE(getKey(mkey, fullfieldname, fromlevel));
				val = encrypt_OPE((uint32_t)val, key);
				if (fromlevel == tolevel) {
					return marshallVal(val);
				}
			}

			if (fromlevel == OPESELF) {

				fromlevel  = increaseLevel(fromlevel, ft, oOPE);
				AES_KEY * key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
				val = encrypt_SEM(val, key, salt);
				if (fromlevel == tolevel) {
					return marshallVal(val);
				}
			}

			assert_s(false, "nothing higher than OPE_SEM");

			return "";
		}
		case oAGG: {
			uint64_t val = unmarshallVal(data);
			unsigned char * uval;
			if (fromlevel == PLAIN_AGG) {
				uval = encrypt_Paillier(val);
				fromlevel  = increaseLevel(fromlevel, ft, oAGG);
				if (fromlevel == tolevel) {
					return marshallBinary(uval, Paillier_len_bytes);
				}
			}

			assert_s(false, "nothing higher than sem agg");

			return "";
		}
		default: {
			assert_s(false, "no other onions possible\n");
			return "";
		}
		}
		assert_s(false, "no other onions possible\n");
		return "";
	}
	case TYPE_TEXT:{

		switch (o) {
		case oDET: {
			if (fromlevel == PLAIN_DET) {

				data = removeApostrophe(data);

				unsigned int newlen = 0;

				fromlevel  = increaseLevel(fromlevel, ft, oDET);

				AES_KEY * key = get_key_DET(getKey(mkey, fullfieldname, fromlevel));
				unsigned char * uval = encrypt_DET_wrapper(data, key, newlen);
				//cerr << "crypting " << data << " at DET is " << marshallBinary(uval, newlen) << "  ";
				if (fromlevel == tolevel) {
					//cerr << "result is " << marshallBinary(uval, newlen);

					return marshallBinary(uval,newlen);
				}
				fromlevel = increaseLevel(fromlevel, ft, oDET);
				key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
				uval = encrypt_SEM(uval, newlen, key, salt);
				//cerr << "at sem is " << marshallBinary(uval, newlen) << "\n";
				if (fromlevel == tolevel) {
					return marshallBinary(uval,newlen);
				} else {
					assert_s(false, "no higher level than SEMANTIC_DET\n");
				}

			} else {
				assert_s(fromlevel == DET, "expected det level \n");
				unsigned int newlen = 0;
				unsigned char * uval = unmarshallBinary(getCStr(data), data.length(), newlen);

				fromlevel = increaseLevel(fromlevel, ft, oDET);

				AES_KEY * key = get_key_SEM(getKey(mkey, fullfieldname, fromlevel));
				uval = encrypt_SEM(uval, newlen, key, salt);
				if (fromlevel == tolevel) {
					return marshallBinary(uval,newlen);
				} else {
					assert_s(false, "no higher level than SEMANTIC_DET\n");
				}
			}

			assert_s(false, "nothing higher than SEM_DET for text\n");

			return "";
		}
		case oOPE: {
			return "5";
			//not yet implemented
		}
		default: {
			myassert(false, "no valid onion in text \n");
			return "";
		}
		}
		myassert(false, "no valid onion in text \n");
		return "";
	}
	default: {
		myassert(false, "no other types possible \n");
		return "";
	}
	}
	myassert(false, "no other types possible \n");
	return "";

}



uint64_t CryptoManager::encrypt_OPE_onion(string  uniqueFieldName, uint32_t value, uint64_t salt) {
	unsigned char * key;

	uint64_t res = encrypt_OPE(value, uniqueFieldName);

	key = getKey(uniqueFieldName, SEMANTIC_OPE);

	AES_KEY * aesKey = get_key_SEM(key);
	res = encrypt_SEM(res, aesKey, salt);

	return res;
}

uint64_t CryptoManager::encrypt_DET_onion(string  uniqueFieldName, uint32_t value, uint64_t salt) {
	unsigned char * key;


	//cout << "KEY USED TO ENCRYPT field to JOINDET " << uniqueFieldName << " " << marshallKey(getKey("join", DETJOIN)) << "\n"; fflush(stdout);

	key = getKey("join", DETJOIN);
	AES_KEY * aesKey = get_key_DET(key);
	uint64_t res = encrypt_DET(value, aesKey);

	//cout << "join det enc is " << res << "\n";
	//cout << "KEY USED TO ENCRYPT field to DET " << uniqueFieldName << " " << marshallKey(getKey(uniqueFieldName, DET)) << "\n"; fflush(stdout);


	key = getKey(uniqueFieldName, DET);
	aesKey = get_key_DET(key);
	res =  encrypt_DET(res, aesKey);

	//cout << "det enc is " << res << "\n";

	//cout << "KEY USED TO ENCRYPT field to SEM " << uniqueFieldName << " " << marshallKey(getKey(uniqueFieldName, SEMANTIC)) << "\n"; fflush(stdout);


	key = getKey(uniqueFieldName, SEMANTIC_DET);
	aesKey = get_key_SEM(key);
	res = encrypt_SEM(res, aesKey, salt);

	return res;

}


unsigned char * CryptoManager::encrypt_text_DET_onion(string uniqueFieldName, string value,  uint64_t salt, unsigned int & len) {

	//cerr << "encrypting onion with fname " << uniqueFieldName.c_str() << "\n";
	unsigned char * key;

	key = getKey(uniqueFieldName, DET);
	AES_KEY * aesKey = get_key_DET(key);

	len = value.length();

	unsigned char * res =  encrypt_DET_wrapper(value, aesKey, len);

	key = getKey(uniqueFieldName, SEMANTIC_DET);
	aesKey = get_key_SEM(key);
	return encrypt_SEM(res, len, aesKey, salt);

}


uint64_t CryptoManager::encrypt_DET_onion(string  uniqueFieldName, string value, uint64_t salt) {
	unsigned char * key;

	key = getKey(uniqueFieldName, DET);
	AES_KEY * aesKey = get_key_DET(key);
	uint64_t res =  encrypt_DET(value, aesKey);

	key = getKey(uniqueFieldName, SEMANTIC_DET);
	aesKey = get_key_SEM(key);
	res = encrypt_SEM(res, aesKey, salt);

	return res;

}



string assembleWords(list<string> * words);
list<string> * getWords(string text);


uint32_t CryptoManager::encrypt_VAL(string  uniqueFieldName, uint32_t value, uint64_t salt) {
	unsigned char * key = getKey(uniqueFieldName, SEMANTIC_VAL);
	//cout << "key to encrypt " << uniqueFieldName << " is " << marshallKey(key) << "\n";
	AES_KEY * aesKey = get_key_SEM(key);
	//cout << "value is " << value << " encryption is " << marshallVal(encrypt_SEM(value, aesKey, salt)) << "\n";
	return encrypt_SEM(value, aesKey, salt);
}

unsigned char * CryptoManager::encrypt_VAL(string uniqueFieldName, string value, uint64_t salt) {
	unsigned char * key = getKey(uniqueFieldName, SEMANTIC_VAL);
	AES_KEY * aesKey = get_key_SEM(key);
	return encrypt_SEM(value, aesKey, salt);
}


unsigned char* CryptoManager::getKey(string  uniqueFieldName, SECLEVEL sec) {
	return getKey(masterKey, uniqueFieldName, sec);
}



unsigned char* CryptoManager::getKey(AES_KEY * masterKey, string  uniqueFieldName, SECLEVEL sec) {
	string id = uniqueFieldName + marshallVal((unsigned int) sec);

	unsigned int resLen = AES_KEY_SIZE/bitsPerByte;

	if (id.length() <= resLen) {
		unsigned char * result = new unsigned char[resLen];
		memset(result, 0, resLen);
		memcpy(result, uniqueFieldName.c_str(), id.length());
		return result;
	}

	//need to take a hash  because it is too big
	unsigned char * concat = new unsigned char[id.length()];
	memcpy(concat, id.c_str(), id.length());
	unsigned char * shaDigest = new unsigned char[SHA_DIGEST_LENGTH];
	SHA1(concat, id.length(), shaDigest);

	concat = adjustLen(shaDigest, SHA_DIGEST_LENGTH, AES_BLOCK_BYTES);

	unsigned char * result = new unsigned char[AES_BLOCK_BYTES];

	AES_encrypt(concat, result, masterKey);

	return result;
}


string CryptoManager::marshallKey(const unsigned char * key) {
	// we will be sending key as two big nums
	string res = "";

	for (unsigned int i = 0; i < AES_KEY_SIZE/bitsPerByte; i++) {
		res = res + marshallVal((unsigned int)(key[i])) + ",";
	}

	//remove last comma
	res[res.length()-1] = ' ';

	return res;
}


unsigned char * CryptoManager::unmarshallKey(string key) {

	list<string> words = parse((key + '\0').c_str(),"", ", );", "");

	myassert(words.size() == AES_KEY_BYTES, "the given key string " + key + " is invalid");

	unsigned char * reskey = new unsigned char[AES_KEY_BYTES];
	int i = 0;
	list<string>::iterator wordsIt = words.begin();

	while (wordsIt != words.end()) {
		uint64_t val = unmarshallVal(*wordsIt);
		myassert((val >= 0) && (val < 256), "invalid key -- some elements are bigger than bytes " + key);
		reskey[i] = (unsigned char) (val % 256);
		wordsIt++; i++;
	}

	return reskey;
}


AES_KEY * CryptoManager::get_key_SEM(const unsigned char * key){
	myassert(key!=NULL, "given key is null");
	AES_KEY * aes_key = new AES_KEY();

	if (AES_set_encrypt_key(key, AES_KEY_SIZE, aes_key) <0) {
		myassert(false, "problem with AES set encrypt ");
	}

	return aes_key;

}

uint64_t getXORValue(uint64_t salt, AES_KEY * aes_key) {
	unsigned char * plaintext = BytesFromInt(salt, AES_BLOCK_BYTES);
	unsigned char * ciphertext = new unsigned char[AES_BLOCK_BYTES];
	AES_encrypt(plaintext, ciphertext, aes_key);

	uint64_t res = IntFromBytes(ciphertext, AES_BLOCK_BYTES);

	free(plaintext);
	free(ciphertext);


	return res;
}

uint64_t CryptoManager::encrypt_SEM(uint64_t ptext, AES_KEY * key, uint64_t salt) {

	return ptext ^ getXORValue(salt, key);

}

uint64_t CryptoManager::decrypt_SEM(uint64_t ctext, AES_KEY * key, uint64_t salt) {
	return ctext ^ getXORValue(salt, key);
}


uint32_t CryptoManager::encrypt_SEM(uint32_t ptext, AES_KEY * key, uint64_t salt) {
	return ptext ^ (getXORValue(salt, key) % MAX_UINT32_T);
}



uint32_t CryptoManager::decrypt_SEM(uint32_t ctext, AES_KEY * key, uint64_t salt) {
	return ctext ^ (getXORValue(salt, key) % MAX_UINT32_T);
}


unsigned char * getXorVector(unsigned int len, AES_KEY * key, uint64_t salt) {

	unsigned int AESBlocks = len / AES_BLOCK_BYTES;
	if (AESBlocks * AES_BLOCK_BYTES < len) {
		AESBlocks++;
	}

	//construct vector with which we will XOR
	unsigned char * xorVector = new unsigned char[AESBlocks * AES_BLOCK_BYTES];

	for (unsigned int i = 0; i < AESBlocks; i++) {
		AES_encrypt(BytesFromInt(salt+i, AES_BLOCK_BYTES), xorVector + i*AES_BLOCK_BYTES, key);
	}

	return xorVector;
}

unsigned char * CryptoManager::encrypt_SEM(string ptext, AES_KEY * key, uint64_t salt) {

	unsigned char * puchar = (unsigned char *) getCStr(ptext);
	unsigned char * res =  encrypt_SEM(puchar, ptext.length(), key, salt);
	free(puchar);

	return res;

}	

unsigned char * CryptoManager::encrypt_SEM(unsigned char * & ptext, unsigned int len, AES_KEY * key, uint64_t salt) {

  //cerr << "to encrypt SEM: len is  " << len << " data is "; myPrint(ptext, len); cerr << "\n";


	unsigned char * xorVector = getXorVector(len, key, salt);
	unsigned char * result = new unsigned char[len];

	for (unsigned int i = 0; i < len; i++) {
		result[i] = ptext[i] ^ xorVector[i];
	}

	//cerr << "result of encrypt sem is len " << len << " data is "; myPrint(result, len);

	free(xorVector);

	return result;
}

unsigned char * CryptoManager::decrypt_SEM(unsigned char *  ctext, unsigned int len, AES_KEY * key, uint64_t salt) {
	//cerr << "to decrypt SEM of len " << len << " data is "; myPrint(ctext, len); cerr << "\n";

	unsigned char * xorVector = getXorVector(len, key, salt);

	unsigned char * res = new unsigned char[len];

	for (unsigned int i = 0; i < len; i++) {
		res[i] = ctext[i] ^ xorVector[i];
	}

	free(xorVector);
	//cerr << "Result of decrypt sem has len " << len << " and data is "; myPrint(res, len); cerr << "\n";
	return res;

}




bool isReadable(unsigned char c) {

	if (((c>=0) && (c <= 31)) || ((c>=127) && (c<=255))) {
		return false;
	}

	return true;

}

void CryptoManager::setMasterKey(unsigned char * masterKey) {

	this->masterKey = new AES_KEY();

	AES_set_encrypt_key(masterKey, AES_KEY_SIZE, this->masterKey);

	RAND_seed(masterKey, MASTER_KEY_SIZE);

	SetSeed(ZZFromBytes(masterKey, MASTER_KEY_SIZE));
}


/*
string CryptoManager::decrypt_SEM_toString(unsigned char * etext, unsigned int elen, AES_KEY * key, uint64_t salt) {

    unsigned char * xorVector = getXorVector(elen, key, salt);   

    unsigned char c;
    string result = "";
    for (unsigned int i = 0; i < elen; i++) {
	c = etext[i] ^ xorVector[i];
	myassert(isReadable(c), "decrypt SEM failed -- non readable characters");
	result = result + (char)(c);
    }

    return result;

}
 */
OPE * CryptoManager::get_key_OPE(unsigned char * key) { //key must have OPE_KEY_SIZE
	return new OPE(key, OPE_PLAINTEXT_SIZE, OPE_CIPHERTEXT_SIZE);
}

unsigned char * CryptoManager::encrypt_OPE(unsigned char plaintext[], OPE * ope) {
	//return randomBytes(OPE_PLAINTEXT_SIZE);
	//cerr << "ope!\n";
	return ope->encrypt(plaintext);
}

uint64_t CryptoManager::encrypt_OPE_text_wrapper(const string & plaintext, OPE * ope) {

	unsigned int len = plaintext.length();

	unsigned int prefix = OPE_PLAINTEXT_SIZE/bitsPerByte;

	uint32_t val = 0;

	for (unsigned i = 0; i < min(prefix, len); i++) {
		val = val*10 + plaintext[i];
	}

	for (unsigned int i = 0; i < prefix - len; i++) {
		val = val * 10 + 0;
	}

	return ope->encrypt(val);

}


unsigned char * CryptoManager::decrypt_OPE(unsigned char ciphertext[], OPE * ope) {
	//cerr << "ope!\n";
	return ope->decrypt(ciphertext);
}

uint64_t CryptoManager::encrypt_OPE(uint32_t plaintext, OPE * ope) {
	//return 3;
	//cerr << "ope!\n";
	return ope->encrypt(plaintext);
}

uint32_t CryptoManager::decrypt_OPE(uint64_t ciphertext, OPE * ope) {
	//cerr << "ope!\n";
	return ope->decrypt(ciphertext);
}

uint64_t CryptoManager::encrypt_OPE(uint32_t plaintext, string uniqueFieldName) {
	//cerr << "ope!\n";
	if (useEncTables) {
		map<string, map<int, uint64_t> >::iterator it = OPEEncTable.find(uniqueFieldName);
		assert_s(it != OPEEncTable.end(), string(" there should be entry in OPEEncTables for ") + uniqueFieldName );
		map<int, uint64_t>::iterator sit = it->second.find(plaintext);
		if (sit != it->second.end()) {
			if (VERBOSE) {cerr << "OPE hit for " << plaintext << " \n";}
			return sit->second;
		}
		cerr << "OPE miss for " << plaintext << " \n";
	}

	return encrypt_OPE(plaintext, get_key_OPE(getKey(uniqueFieldName, OPESELF)));
}


AES_KEY * CryptoManager::get_key_DET(const unsigned char * key) {
	myassert(key!=NULL, "given key is null");
	AES_KEY * aes_key = new AES_KEY();

	if (AES_set_encrypt_key(key, AES_KEY_SIZE, aes_key) <0) {
		myassert(false, "problem with AES set encrypt ");
	}
	return aes_key;

}

/*
AES_KEY * CryptoManager::get_dkey_DET(unsigned char * key) {
	myassert(key!=NULL, "given key is null");
	AES_KEY * aes_key = new AES_KEY();

	if (AES_set_decrypt_key(key, AES_KEY_SIZE, aes_key) <0) {
		myassert(false, "problem with AES set decrypt ");
	}
	return aes_key;

}
*/
//TODO: this needs to be fixed, perhaps use evp
uint64_t CryptoManager::encrypt_DET(uint64_t plaintext, AES_KEY * key) {

	return encrypt_SEM(plaintext, key, 1);
	/*
	unsigned char * plainBytes = BytesFromInt(plaintext, AES_BLOCK_BYTES);
	unsigned char * ciphertext = new unsigned char[AES_BLOCK_BYTES];
	AES_encrypt(plainBytes, ciphertext, key);

	return IntFromBytes(ciphertext, AES_BLOCK_BYTES);
	 */
}

uint64_t CryptoManager::decrypt_DET(uint64_t  ciphertext, AES_KEY * key) {

	return decrypt_SEM(ciphertext, key, 1);
	/*
	unsigned char * ciphBytes = BytesFromInt(ciphertext, AES_BLOCK_BYTES);
	unsigned char * plaintext = new unsigned char[AES_BLOCK_BYTES];
	AES_decrypt(ciphBytes, plaintext, key);

	return IntFromBytes(plaintext, AES_BLOCK_BYTES);
	 */
}

uint64_t CryptoManager::encrypt_DET(uint32_t plaintext, AES_KEY * key) {

	return encrypt_SEM((uint64_t) plaintext, key, 1);

	/*
	unsigned char * plainBytes = BytesFromInt((uint64_t)plaintext, AES_BLOCK_BYTES);
	unsigned char * ciphertext = new unsigned char[AES_BLOCK_BYTES];
	AES_encrypt(plainBytes, ciphertext, key);

	cout << "to encrypt for JOIN <" << plaintext << "> result is " << IntFromBytes(ciphertext, AES_BLOCK_BYTES) << "\n"; fflush(stdout);

	return IntFromBytes(ciphertext, AES_BLOCK_BYTES);*/

}

//AES_K(hash(test))
uint64_t CryptoManager::encrypt_DET(string plaintext, AES_KEY*key) {


	unsigned int plainLen = plaintext.size();
	unsigned char * plainBytes = (unsigned char*) getCStr(plaintext);

	unsigned char * shaDigest = new unsigned char[SHA_DIGEST_LENGTH];
	SHA1(plainBytes, plainLen, shaDigest);

	shaDigest = adjustLen(shaDigest, SHA_DIGEST_LENGTH/bitsPerByte, AES_BLOCK_BYTES);

	unsigned char * ciphertext = new unsigned char[AES_BLOCK_BYTES];
	AES_encrypt(shaDigest, ciphertext, key);

	return IntFromBytes(ciphertext, AES_BLOCK_BYTES);
}

void xorWord(string word, AES_KEY * key, int salt, unsigned char * ciph, unsigned int pos) {

	unsigned int plen = word.length();
	unsigned char * xorVector = getXorVector(plen, key, salt);
	unsigned char * pvec = (unsigned char*) getCStr(word);

	for (unsigned int i = 0; i < plen; i++) {
		ciph[pos+i] = pvec[i] ^ xorVector[i];
	}

}

string unxorWord(AES_KEY * key, int salt, unsigned char * ciph, unsigned int len) {
	string res = "";
	unsigned char * xorVector = getXorVector(len, key, salt);

	for (unsigned int i = 0; i < len; i++) {
		res = res + (char)(ciph[i] ^ xorVector[i]);
	}

	return res;
}
void CryptoManager::encrypt_DET_search(list<string> * words, AES_KEY * key, unsigned char * & ciph, unsigned int & len) {

	len = len + words->size();

	ciph = new unsigned char[len];

	int index = 0;
	int pos = 0;
	for (list<string>::iterator it = words->begin(); it != words->end(); it++) {
		//cerr << "word len is " << it->length() << "\n";
		if (it->length() > 255) {*it = it->substr(0, 254);}
		ciph[pos] = it->length();
		pos++;
		xorWord(*it, key, index, ciph, pos);
		pos += it->length();
		index++;
	}

	//cerr << "total len is " << len << " CIPH after enc "; myPrint(ciph, len); cerr << "\n";

}

list<string> * CryptoManager::decrypt_DET_search(unsigned char * ciph, unsigned int len,  AES_KEY * key) {

	//cerr << "CIPH to decrypt " ; myPrint(ciph, len); cerr << "\n";

	unsigned int pos = 0;
	int index = 0;
	list<string> * res = new list<string>();

	while (pos < len) {
		int wlen = ciph[pos];
		//cerr << "wlen is " << wlen << "\n";
		pos++;
		res->push_back(unxorWord(key, index, ciph+pos, wlen));
		index++;
		pos = pos + wlen;
	}

	return res;
}



//returns the concatenation of all words in the given list
string assembleWords(list<string> * words) {
	string res = "";

	for (list<string>::iterator it = words->begin(); it != words->end(); it++) {
		res = res + *it;
	}

	return res;
}


//returns a list of words and separators
list<string> * getWords(string text) {

	list<string> * words =  new list<string>;

	unsigned int len = text.length();

	char * textVec = getCStr(text);

	for (unsigned int pos = 0; pos < len; )
	{
		string word = "";
		while (pos < len && wordSeparators.find(textVec[pos]) == string::npos) {
			word = word + textVec[pos];
			pos++;
		}
		if (word.length() > 0) {
			words->push_back(word);
		}

		string sep = "";
		while (pos < len && wordSeparators.find(textVec[pos]) != string::npos) {
			sep = sep + textVec[pos];
			pos++;
		}
		myassert(pos == len || sep.length() > 0, "error");

		if (sep.length() > 0) {
			words->push_back(sep);
		}

	}





	return words;
}




unsigned char * CryptoManager::encrypt_DET_wrapper(string text, AES_KEY * key, unsigned int & len) {
	unsigned char * ciph;
	len = text.length();
	CryptoManager::encrypt_DET_search(getWords(text), key, ciph, len);

	return ciph;

}
string CryptoManager::decrypt_DET_wrapper(unsigned char * ctext, unsigned int len, AES_KEY * key) {
	return assembleWords(CryptoManager::decrypt_DET_search(ctext, len, key));
}



unsigned char * CryptoManager::encrypt_Paillier(int val) {
	//cerr << "paillier!\n";
	if (useEncTables) {
		map<int, list<unsigned char *> >::iterator it = HOMEncTable.find(val);
		if (it != HOMEncTable.end()) {
			if (it->second.size() > 0) {
				unsigned char * res = it->second.front();
				it->second.pop_front();
				if (VERBOSE) {cerr << "HOM hit for " << val << " \n";}
				return res;
			}
		}

		if (VERBOSE) {cerr << "HOM miss for " << val << " \n";}

	}

	ZZ r = RandomLen_ZZ(Paillier_len_bits/2) % Paillier_n;
	//myassert(Paillier_g < Paillier_n2, "error: g > n2!");
	ZZ c = PowerMod(Paillier_g, to_ZZ(val) + Paillier_n*r, Paillier_n2);

	//cerr << "Paillier encryption is " << c << "\n";
	return BytesFromZZ(c, Paillier_len_bytes);

}

int CryptoManager::decrypt_Paillier(unsigned char * ciphertext) {
	//cerr << "paillier!\n";
	//cerr << "to Paillier decrypt "; myPrint(ciphertext, Paillier_len_bytes); cerr << "\n";
	//cerr << "N2 is " << Paillier_n2 << "\n";
	ZZ c = ZZFromBytes(ciphertext, Paillier_len_bytes);
	//cerr << "zz to decrypt " << c << "\n";
	//myassert(c < Paillier_n2, "error: c > Paillier_n2");
	ZZ m = MulMod(  Paillier_L(PowerMod(c, Paillier_lambda, Paillier_n2), Paillier_n),
			Paillier_dec_denom,
			Paillier_n);

	//cerr << "Paillier N2 is " << Paillier_n2 << "\n";
	//cerr << "Paillier N2 in bytes is "; myPrint(BytesFromZZ(Paillier_n2, Paillier_len_bytes), Paillier_len_bytes); cerr << "\n";
	//cerr << "result is " << m << "\n";
	return to_int(m);
}


unsigned char * CryptoManager::getPKInfo() {
	return BytesFromZZ(Paillier_n2, Paillier_len_bytes);

}


void CryptoManager::createEncryptionTables(int noOPE, int noHOM, list<string>  fieldsWithOPE) {

	int encryptionsOfOne = 100;
	int noEncryptions = 5;

	this->noOPE = noOPE;
	this->noHOM = noHOM;

	OPEEncTable = map<string, map<int, uint64_t> >();
	HOMEncTable = map<int, list<unsigned char*> >();


	struct timeval starttime, endtime;
	//OPE

	gettimeofday(&starttime, NULL);

	for (list<string>::iterator it = fieldsWithOPE.begin(); it != fieldsWithOPE.end(); it++) {
		string anonName = *it;
		OPEEncTable[anonName] = map<int, uint64_t>();
		OPE * currentKey = get_key_OPE(getKey(anonName, OPESELF));
		for (int i = 0; i < noOPE; i++) {
			OPEEncTable[anonName][i] = encrypt_OPE(i, currentKey);
		}

	}
	gettimeofday(&endtime, NULL);
	cerr << "time per OPE " << timeInSec(starttime, endtime) * 1000.0 / noOPE << "\n";


	gettimeofday(&starttime, NULL);
	// HOM
	for (int i = 0; i < encryptionsOfOne; i++) {
		HOMEncTable[1] = list<unsigned char *>();
		HOMEncTable[1].push_back(encrypt_Paillier(1));
	}

	for (int i = 0; i < noHOM; i++) {
		if (i != 1) {
			HOMEncTable[i] = list<unsigned char *>();
			for (int j = 0; j < noEncryptions; j++) {
				HOMEncTable[i].push_back(encrypt_Paillier(i));
			}
		}
	}


	gettimeofday(&endtime, NULL);
	cerr << "per HOM " << timeInSec(starttime, endtime)*1000.0 / (encryptionsOfOne + noHOM * noEncryptions) << " \n";
	cerr << "entries in OPE table are \n";
	for (map<string, map<int, uint64_t> >::iterator it = OPEEncTable.begin(); it != OPEEncTable.end(); it++) {
		cerr << it->first << " ";
	}
	cerr << "\n entries for HOM are \n";
	for (map<int, list<unsigned char*> >::iterator it = HOMEncTable.begin(); it != HOMEncTable.end(); it++) {
		cerr << it->first << " ";
	}
	cerr << "\n";

	useEncTables = true;

}


void CryptoManager::replenishEncryptionTables() {
	assert_s(false, "unimplemented replenish");
}



//**************** Public Key Cryptosystem (PKCS) ****************************************/

//marshall key
unsigned char *DER_encode_RSA_public(RSA *rsa, int *len) {
  unsigned char *buf, *next;

  *len = i2d_RSAPublicKey(rsa, 0);
  if (!(buf = next = (unsigned char *)malloc(*len))) return 0;
  i2d_RSAPublicKey(rsa, &next); /* If we use buf here, return buf; becomes wrong */
  return buf;
}

RSA *DER_decode_RSA_public(unsigned char *buf, long len) {
  return d2i_RSAPublicKey(0, (const unsigned char **)&buf, len);
}

//marshall key
unsigned char *DER_encode_RSA_private(RSA *rsa, int *len) {
  unsigned char *buf, *next;

  *len = i2d_RSAPrivateKey(rsa, 0);
  if (!(buf = next = (unsigned char *)malloc(*len))) return 0;
  i2d_RSAPrivateKey(rsa, &next); /* If we use buf here, return buf; becomes wrong */
  return buf;
}

RSA *DER_decode_RSA_private(unsigned char *buf, long len) {
  return d2i_RSAPrivateKey(0, (const unsigned char **)&buf, len);
}

void remove_private_key(RSA *r) {
  r->d = r->p = r->q = r->dmp1 = r->dmq1 = r->iqmp = 0;
}

//Credits: the above five functions are from "secure programming cookbook for C++"

void CryptoManager::generateKeys(PKCS * & pk, PKCS * & sk) {
	cerr << "pkcs generate\n";
	PKCS * key =  RSA_generate_key(PKCS_bytes_size*8, 3, NULL, NULL);

	sk = RSAPrivateKey_dup(key);

	pk = key;
	remove_private_key(pk);

}

binary CryptoManager::marshallKey(PKCS * mkey, bool ispk, int & len) {
	cerr << "pkcs encrypt\n";
	binary key;
	if (!ispk) {
		key = DER_encode_RSA_private(mkey, &len);

	} else {
		key = DER_encode_RSA_public(mkey, &len);

	}
	assert_s(len >= 1, "issue with RSA pk \n");
	return key;
}


PKCS * CryptoManager::unmarshallKey(binary key, int keylen, bool ispk) {
    cerr << "pkcs decrypt\n";
  //cerr << "before \n";
	if (ispk) {
		return DER_decode_RSA_public(key, keylen);

	} else {
		return DER_decode_RSA_private(key, keylen);
	}

}

unsigned char * CryptoManager::encrypt(PKCS * key,  unsigned char * from, int fromlen, int & len) {
	len = RSA_size(key);

	binary tocipher = new unsigned char[len];

	RSA_public_encrypt(fromlen, from, tocipher, key, RSA_PKCS1_OAEP_PADDING);

	return tocipher;
}


unsigned char * CryptoManager::decrypt(PKCS * key, unsigned char * fromcipher, int fromlen, int & len) {
	assert_s(fromlen == RSA_size(key), "fromlen is not RSA_size");
	binary toplain = new unsigned char[fromlen];

	len = RSA_private_decrypt(fromlen, fromcipher, toplain, key, RSA_PKCS1_OAEP_PADDING);

	return toplain;
}

void CryptoManager::freeKey(PKCS * key) {
	RSA_free(key);
}

//***************************************************************************************/

CryptoManager::~CryptoManager() {
	free(masterKey);
	free(masterKeyBytes);

	map<string, map<int, uint64_t> >::iterator it = OPEEncTable.begin();

	for (; it != OPEEncTable.end(); it++) {
		it->second.clear();
	}

	OPEEncTable.clear();

	map<int, list<unsigned char*> >::iterator homit = HOMEncTable.begin();

	for (; homit != HOMEncTable.end(); homit++) {
		homit->second.clear();
	}

	HOMEncTable.clear();

}
