/*
 * TestCrypto
 * -- tests crypto work; migrated from test.cc
 *
 *
 */

#include "TestCrypto.h"


TestCrypto::TestCrypto()
{
}

TestCrypto::~TestCrypto()
{
}

static void
testOPE()
{

    const unsigned int OPEPlaintextSize = 32;
    const unsigned int OPECiphertextSize = 128;

    unsigned char key[AES_KEY_SIZE/
                      bitsPerByte] =
    {158, 242, 169, 240, 255, 166, 39, 177, 149, 166, 190, 237, 178, 254, 187,
     40};

    OPE * ope = new OPE((const char *) key, OPEPlaintextSize,
                        OPECiphertextSize);

    unsigned char plaintext[OPEPlaintextSize/bitsPerByte] = {74, 95, 221, 84};
    string plaintext_s = string((char *) plaintext,
                                OPEPlaintextSize/bitsPerByte);

    string ciphertext = ope->encrypt(plaintext_s);
    string decryption = ope->decrypt(ciphertext);

    assert_s(plaintext_s == decryption,
             "OPE test failed: decryption does not match plaintext");
    assert_s(plaintext_s.compare(
                 ciphertext) != 0,
             "OPE test failed: ciphertext is the same as plaintext");
}

static void
testHDG()
{
    unsigned int len = 16;   //bytes
    unsigned int bitsPrecision = len * bitsPerByte + 10;
    ZZ K = ZZFromString(randomBytes(len));
    ZZ N1 = ZZFromString(randomBytes(len));
    ZZ N2 = ZZFromString(randomBytes(len));
    ZZ SEED = ZZFromString(randomBytes(len));

    ZZ sample = HGD(K, N1, N2, SEED, len*bitsPerByte, bitsPrecision);

    cerr << "N1 is "; myPrint(StringFromZZ(N1)); cerr << "\n";
    cerr << "N2 is "; myPrint(StringFromZZ(N2)); cerr << "\n";
    cerr << "K is "; myPrint(StringFromZZ(K)); cerr << "\n";
    cerr << "HGD sample is ";
    myPrint(StringFromZZ(sample)); cerr << "\n";
}

static void
testPKCS()
{

}

unsigned int * to_vec(const list<unsigned int> & lst);

unsigned int *
to_vec(const list<unsigned int> & lst) {
	unsigned int * vec = new unsigned int[lst.size()];

	unsigned int index = 0;
	for (list<unsigned int>::const_iterator it = lst.begin(); it != lst.end();it++) {
		vec[index] = *it;
		index++;
	}

	return vec;
}


static void
testSWPSearch() {
	cout << "   -- test Song-Wagner-Perrig crypto ... \n";

	Binary mediumtext = Binary::toBinary("hello world!");
	Binary smalltext = Binary::toBinary("hi");
	Binary emptytext = Binary::toBinary("");
	Binary exacttext = Binary::toBinary("123456789012345");

	cout << "		+ test encrypt/decrypt \n";

	list<Binary> lst = {mediumtext, smalltext, emptytext, exacttext};

	Binary key = Binary::toBinary("this is a secret key").subbinary(0, 16);

	//test encryption/decryption

	list<Binary> * result = SWP::encrypt(key, lst);
	list<Binary> * decs = SWP::decrypt(key, *result);


	list<Binary>::iterator lstit = lst.begin();

	unsigned int index = 0;
	for (list<Binary>::iterator it = decs->begin(); it!=decs->end(); it++) {
		assert_s((*it) == (*lstit), "incorrect decryption at " + StringFromVal(index));
		index++;
		lstit++;
	}

	//test searchability

	cout << "		+ test searchability \n";

	Binary word1 = Binary::toBinary("ana");
	Binary word2 = Binary::toBinary("dana");
	Binary word3 = Binary::toBinary("n");
	Binary word4 = Binary::toBinary("");
	Binary word5 = Binary::toBinary("123ana");

	list<Binary> vec1 = {word1, word2, word1, word3, word4, word5, word1, word1};
	list<Binary> vec2 = {};
	list<Binary> vec3 = {word2, word3, word4, word5};
	list<Binary> vec4 = {word1};

	list<Binary> * encs = SWP::encrypt(key, vec1);
	Token token = SWP::token(key, word1);

	list<unsigned int> * indexes = SWP::search(token, *encs);
	assert_s(indexes->size() == 4, string("incorrect number of findings in vec1, expected 4, returned ") + StringFromVal(indexes->size()));
	unsigned int * vec_ind = to_vec(*indexes);
	assert_s(vec_ind[0] == 0, "incorrect index found for entry 0");
	assert_s(vec_ind[1] == 2, "incorrect index found for entry 1");
	assert_s(vec_ind[2] == 6, "incorrect index found for entry 2");
	assert_s(vec_ind[3] == 7, "incorrect index found for entry 3");

	indexes = SWP::search(SWP::token(key, word1), *SWP::encrypt(key, vec2));
	assert_s(indexes->size() == 0, "incorrect number of findings in vec2");

	indexes = SWP::search(SWP::token(key, word1), *SWP::encrypt(key, vec3));
	assert_s(indexes->size() == 0, "incorrect number of findings in vec3");

	indexes = SWP::search(SWP::token(key, word1), *SWP::encrypt(key, vec4));
	assert_s(indexes->size() == 1, "incorrect number of findings in vec4");
	assert_s(indexes->front() == 0, "incorrect index found for entry 0 in vec4");

	//test encrypt/decrypt wrappers

	cout << "		+ test wrappers \n";

	list<Binary> lstw = {mediumtext, smalltext, emptytext,  exacttext};

	Binary encw = SWP::encryptWrapper(key, lstw);
	list<Binary> * decw = SWP::decryptWrapper(key, encw);

	list<Binary>::iterator wit = lstw.begin();

	index = 0;
	for (list<Binary>::iterator it = decw->begin(); it!=decw->end(); it++) {
		assert_s((*it) == (*wit), "incorrect decryption at " + StringFromVal(index));
		index++;
		wit++;
	}

	//test searchability

	Binary overall_ciph = SWP::encryptWrapper(key, vec1);
	token = SWP::token(key, word1);

	indexes = SWP::searchWrapper(token, overall_ciph);
	assert_s(indexes->size() == 4, string("incorrect number of findings in vec1, expected 4, returned ") + StringFromVal(indexes->size()));
	vec_ind = to_vec(*indexes);
	assert_s(vec_ind[0] == 0, "incorrect index found for entry 0");
	assert_s(vec_ind[1] == 2, "incorrect index found for entry 1");
	assert_s(vec_ind[2] == 6, "incorrect index found for entry 2");
	assert_s(vec_ind[3] == 7, "incorrect index found for entry 3");


	indexes = SWP::searchWrapper(SWP::token(key, word1), SWP::encryptWrapper(key, vec2));
	assert_s(indexes != NULL && indexes->size() == 0, "incorrect number of findings in vec2");

	indexes = SWP::searchWrapper(SWP::token(key, word1), SWP::encryptWrapper(key, vec3));
	assert_s(indexes != NULL && indexes->size() == 0, "incorrect number of findings in vec3");

	indexes = SWP::searchWrapper(SWP::token(key, word1), SWP::encryptWrapper(key, vec4));
	assert_s(indexes != NULL && indexes->size() == 1, "incorrect number of findings in vec4");
	assert_s(indexes->front() == 0, "incorrect index found for entry 0 in vec4");


	cout << "   -- OK \n";
}

void
TestCrypto::run(int argc, char ** argv)
{
    cerr << "TESTING CRYPTO" << endl;
    cerr << "Testing OPE..." << endl;
    testOPE();
    cerr << "Testing HDG..." << endl;
    testHDG();
    cerr << "Testing PKCS..." << endl;
    testPKCS();
    cerr << "Testing SWP Search ... " << endl;
    testSWPSearch();
    cerr << "Done! All crypto tests passed." << endl;
}
