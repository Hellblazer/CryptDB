#pragma once

/*
 * cdb_rewrite.hh
 *
 *  Created on: Sep 29, 2011
 *      Author: raluca
 *
 *  TODO: need to integrate it with util.h: some declarations are repeated
 */

typedef enum onion {oDET, oOPE, oAGG, oNONE, oSWP, oINVALID} onion;

#define SECLEVELS(m)    \
    m(INVALID)          \
    m(PLAIN)            \
    m(PLAIN_DET)        \
    m(DETJOIN)          \
    m(DET)              \
    m(SEMANTIC_DET)     \
    m(PLAIN_OPE)        \
    m(OPEJOIN)          \
    m(OPE)              \
    m(SEMANTIC_OPE)     \
    m(PLAIN_AGG)        \
    m(SEMANTIC_AGG)     \
    m(PLAIN_SWP)        \
    m(SWP)              \
    m(SEMANTIC_VAL)

typedef enum class SECLEVEL {
#define __temp_m(n) n,
SECLEVELS(__temp_m)
#undef __temp_m
    SECLEVEL_LAST
} SECLEVEL;

const string levelnames[] = {
#define __temp_m(n) #n,
SECLEVELS(__temp_m)
#undef __temp_m
    "SECLEVEL_LAST"
};


//a set of encryptions
class EncSet {
public:
    map<onion, SECLEVEL> osl; //max level on each onion
    EncSet(map<onion, SECLEVEL> input);
    EncSet(const EncSet & es);
    EncSet();
    int restrict(onion o, SECLEVEL maxl);
    pair<onion, SECLEVEL> chooseOne() const;//decides which encryption scheme to use out of multiple in a set
    int remove(onion o);
    EncSet intersect(const EncSet & es2) const;
    ~EncSet() {}

};

const EncSet EQ_EncSet = {
		{{oDET, SECLEVEL::DET},
		{oOPE, SECLEVEL::OPE}}
};

const EncSet ORD_EncSet = {
		{{oOPE, SECLEVEL::OPE}}
};

//todo: there should be a map of FULL_EncSets depending on item type
const EncSet FULL_EncSet = {
		{{oDET, SECLEVEL::SEMANTIC_DET},
		 {oOPE, SECLEVEL::SEMANTIC_OPE},
		 {oAGG, SECLEVEL::SEMANTIC_AGG},
		 {oSWP, SECLEVEL::SWP}
		}
};

const EncSet Search_EncSet = {
    {{oSWP, SECLEVEL::SWP}}
};

const EncSet ADD_EncSet = {
    {{oAGG, SECLEVEL::SEMANTIC_AGG}}
};
    
const EncSet EMPTY_EncSet = {
    {{}}
};


class FieldMeta {
public:
    EncSet exposedLevels; //field identifier to max sec level allowed to process a query
    FieldMeta(const EncSet & es) : exposedLevels(es) {}
};

//Metadata about how to encrypt an item
class ItemMeta {
	onion o;
	SECLEVEL uptolevel;
	string basekey;
};

class Analysis {
public:

	map<string, FieldMeta *> fieldToMeta;
	map<string, ItemMeta *> itemToMeta;

	bool hasConverged;

	Analysis() {hasConverged = false;}
};

class FieldReturned {
	bool encrypted;
	bool includeInResult;
	string key;
	unsigned int SaltIndex;
	string nameForReturn;
};

class ReturnMeta {
	vector<FieldReturned *> retFM;
};


class constraints {
public:
	constraints(EncSet t_arg,
			const std::string &why_t_arg,
			Item *why_t_item_arg,
			const constraints *parent_arg)
	: encset(t_arg), soft(false),
	  why_t(why_t_arg), why_t_item(why_t_item_arg),
	  parent(parent_arg)
	{
		if (parent && parent->soft)
			soft = true;
	}

	constraints(EncSet t_arg,
			const std::string &why_t_arg,
			Item *why_t_item_arg,
			const constraints *parent_arg,
			bool soft_arg)
	: encset(t_arg), soft(soft_arg),
	  why_t(why_t_arg), why_t_item(why_t_item_arg),
	  parent(parent_arg)
	{
	}

	EncSet encset;

	bool soft;      /* can be evaluated at proxy */

	string why_t;
	Item *why_t_item;

	const constraints *parent;
};

string  rewrite(const string &db, const string &q, ReturnMeta &rmeta);
