/*
 * TestCrypto
 * -- tests crypto work; migrated from test.cc
 *
 *
 */

#include "TestCrypto.h"
#include "pbkdf2.h"
#include "cryptdb_log.h"

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

	/* This test is outdated.
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
    */
}

static void
testPKCS()
{

}

static void
printhex(const char *s, const u_int8_t *buf, size_t len)
{
    size_t i;

    printf("%s: ", s);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
    fflush(stdout);
}

static void
testPBKDF2(void)
{
    /*
     * Test vectors from RFC 3962
     */
    static struct test_vector {
        u_int rounds;
        const char *pass;
        const char *salt;
        const unsigned char expected[32];
    } test_vectors[] = {
        {
            1,
            "password",
            "ATHENA.MIT.EDUraeburn",
            {
                0xcd, 0xed, 0xb5, 0x28, 0x1b, 0xb2, 0xf8, 0x01,
                0x56, 0x5a, 0x11, 0x22, 0xb2, 0x56, 0x35, 0x15,
                0x0a, 0xd1, 0xf7, 0xa0, 0x4b, 0xb9, 0xf3, 0xa3,
                0x33, 0xec, 0xc0, 0xe2, 0xe1, 0xf7, 0x08, 0x37
            },
        }, {
            2,
            "password",
            "ATHENA.MIT.EDUraeburn",
            {
                0x01, 0xdb, 0xee, 0x7f, 0x4a, 0x9e, 0x24, 0x3e,
                0x98, 0x8b, 0x62, 0xc7, 0x3c, 0xda, 0x93, 0x5d,
                0xa0, 0x53, 0x78, 0xb9, 0x32, 0x44, 0xec, 0x8f,
                0x48, 0xa9, 0x9e, 0x61, 0xad, 0x79, 0x9d, 0x86
            },
        }, {
            1200,
            "password",
            "ATHENA.MIT.EDUraeburn",
            {
                0x5c, 0x08, 0xeb, 0x61, 0xfd, 0xf7, 0x1e, 0x4e,
                0x4e, 0xc3, 0xcf, 0x6b, 0xa1, 0xf5, 0x51, 0x2b,
                0xa7, 0xe5, 0x2d, 0xdb, 0xc5, 0xe5, 0x14, 0x2f,
                0x70, 0x8a, 0x31, 0xe2, 0xe6, 0x2b, 0x1e, 0x13
            },
        }, {
            5,
            "password",
            "\0224VxxV4\022",     /* 0x1234567878563412 */
            {
                0xd1, 0xda, 0xa7, 0x86, 0x15, 0xf2, 0x87, 0xe6,
                0xa1, 0xc8, 0xb1, 0x20, 0xd7, 0x06, 0x2a, 0x49,
                0x3f, 0x98, 0xd2, 0x03, 0xe6, 0xbe, 0x49, 0xa6,
                0xad, 0xf4, 0xfa, 0x57, 0x4b, 0x6e, 0x64, 0xee
            },
        }, {
            1200,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "pass phrase equals block size",
            {
                0x13, 0x9c, 0x30, 0xc0, 0x96, 0x6b, 0xc3, 0x2b,
                0xa5, 0x5f, 0xdb, 0xf2, 0x12, 0x53, 0x0a, 0xc9,
                0xc5, 0xec, 0x59, 0xf1, 0xa4, 0x52, 0xf5, 0xcc,
                0x9a, 0xd9, 0x40, 0xfe, 0xa0, 0x59, 0x8e, 0xd1
            },
        }, {
            1200,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "pass phrase exceeds block size",
            {
                0x9c, 0xca, 0xd6, 0xd4, 0x68, 0x77, 0x0c, 0xd5,
                0x1b, 0x10, 0xe6, 0xa6, 0x87, 0x21, 0xbe, 0x61,
                0x1a, 0x8b, 0x4d, 0x28, 0x26, 0x01, 0xdb, 0x3b,
                0x36, 0xbe, 0x92, 0x46, 0x91, 0x5e, 0xc8, 0x2a
            },
        }, {
            50,
            "\360\235\204\236",     /* g-clef (0xf09d849e) */
            "EXAMPLE.COMpianist",
            {
                0x6b, 0x9c, 0xf2, 0x6d, 0x45, 0x45, 0x5a, 0x43,
                0xa5, 0xb8, 0xbb, 0x27, 0x6a, 0x40, 0x3b, 0x39,
                0xe7, 0xfe, 0x37, 0xa0, 0xc4, 0x1e, 0x02, 0xc2,
                0x81, 0xff, 0x30, 0x69, 0xe1, 0xe9, 0x4f, 0x52
            },
        }
    };

    for (uint i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]);
         i++) {
        struct test_vector *vec = &test_vectors[i];
        LOG(test) << "vector " << i;
        for (uint j = 1; j < 32; j += 3) {
            string k = pbkdf2(string(vec->pass),
                              string(vec->salt),
                              j, vec->rounds);
            if (memcmp(&k[0], vec->expected, j) != 0) {
                printhex(" got", (uint8_t *) &k[0], j);
                printhex("want", vec->expected, j);
                cerr << "pbkdf2 mismatch\n";
            } else {
                // LOG(test) << "pbkdf2 " << i << " " << j << " ok";
            }
        }
    }
}

unsigned int * to_vec(const list<unsigned int> & lst);

unsigned int *
to_vec(const list<unsigned int> & lst)
{
    unsigned int * vec = new unsigned int[lst.size()];

    unsigned int index = 0;
    for (list<unsigned int>::const_iterator it = lst.begin(); it != lst.end();
         it++) {
        vec[index] = *it;
        index++;
    }

    return vec;
}

static void
testSWPSearch()
{
    LOG(test) << "   -- test Song-Wagner-Perrig crypto ...";

    Binary mediumtext = Binary::toBinary("hello world!");
    Binary smalltext = Binary::toBinary("hi");
    Binary emptytext = Binary::toBinary("");
    Binary exacttext = Binary::toBinary("123456789012345");

    LOG(test) << "		+ test encrypt/decrypt";

    list<Binary> lst = {mediumtext, smalltext, emptytext, exacttext};

    Binary key = Binary::toBinary("this is a secret key").subbinary(0, 16);

    //test encryption/decryption

    list<Binary> * result = SWP::encrypt(key, lst);
    list<Binary> * decs = SWP::decrypt(key, *result);

    list<Binary>::iterator lstit = lst.begin();

    unsigned int index = 0;
    for (list<Binary>::iterator it = decs->begin(); it!=decs->end(); it++) {
        assert_s((*it) == (*lstit), "incorrect decryption at " +
                 StringFromVal(
                     index));
        index++;
        lstit++;
    }

    //test searchability

    LOG(test) << "		+ test searchability";

    Binary word1 = Binary::toBinary("ana");
    Binary word2 = Binary::toBinary("dana");
    Binary word3 = Binary::toBinary("n");
    Binary word4 = Binary::toBinary("");
    Binary word5 = Binary::toBinary("123ana");

    list<Binary> vec1 =
    {word1, word2, word1, word3, word4, word5, word1, word1};
    list<Binary> vec2 = {};
    list<Binary> vec3 = {word2, word3, word4, word5};
    list<Binary> vec4 = {word1};

    list<Binary> * encs = SWP::encrypt(key, vec1);
    Token token = SWP::token(key, word1);

    list<unsigned int> * indexes = SWP::search(token, *encs);
    assert_s(indexes->size() == 4,
             string(
                 "incorrect number of findings in vec1, expected 4, returned ")
             +
             StringFromVal(indexes->size()));
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
    assert_s(
        indexes->front() == 0, "incorrect index found for entry 0 in vec4");

    //test encrypt/decrypt wrappers

    LOG(test) << "		+ test wrappers";

    list<Binary> lstw = {mediumtext, smalltext, emptytext,  exacttext};

    Binary encw = CryptoManager::encryptSWP(key, lstw);
    list<Binary> * decw = CryptoManager::decryptSWP(key, encw);

    list<Binary>::iterator wit = lstw.begin();

    index = 0;
    for (list<Binary>::iterator it = decw->begin(); it!=decw->end(); it++) {
        assert_s((*it) == (*wit), "incorrect decryption at " +
                 StringFromVal(index));
        index++;
        wit++;
    }

    //test searchability

    Binary overall_ciph = CryptoManager::encryptSWP(key, vec1);
    token = CryptoManager::token(key, word1);

    indexes = CryptoManager::searchSWP(token, overall_ciph);
    assert_s(indexes->size() == 4,
             string(
                 "incorrect number of findings in vec1, expected 4, returned ")
             +
             StringFromVal(indexes->size()));
    vec_ind = to_vec(*indexes);
    assert_s(vec_ind[0] == 0, "incorrect index found for entry 0");
    assert_s(vec_ind[1] == 2, "incorrect index found for entry 1");
    assert_s(vec_ind[2] == 6, "incorrect index found for entry 2");
    assert_s(vec_ind[3] == 7, "incorrect index found for entry 3");
    assert_s(CryptoManager::searchExists(CryptoManager::token(key,
                                                              word1),
                                         CryptoManager::encryptSWP(key,
                                                                   vec1)),
             "incorrect found flad in vec2");

    indexes = CryptoManager::searchSWP(CryptoManager::token(key,
                                                            word1),
                                       CryptoManager::encryptSWP(key, vec2));
    assert_s(
        indexes != NULL && indexes->size() == 0,
        "incorrect number of findings in vec2");
    assert_s(!CryptoManager::searchExists(CryptoManager::token(key,
                                                               word1),
                                          CryptoManager::encryptSWP(key,
                                                                    vec2)),
             "incorrect found flad in vec2");

    indexes = CryptoManager::searchSWP(CryptoManager::token(key,
                                                            word1),
                                       CryptoManager::encryptSWP(key, vec3));
    assert_s(
        indexes != NULL && indexes->size() == 0,
        "incorrect number of findings in vec3");
    assert_s(!CryptoManager::searchExists(CryptoManager::token(key,
                                                               word1),
                                          CryptoManager::encryptSWP(key,
                                                                    vec3)),
             "incorrect found flag in vec3");

    indexes = CryptoManager::searchSWP(CryptoManager::token(key,
                                                            word1),
                                       CryptoManager::encryptSWP(key, vec4));
    assert_s(
        indexes != NULL && indexes->size() == 1,
        "incorrect number of findings in vec4");
    assert_s(
        indexes->front() == 0, "incorrect index found for entry 0 in vec4");
    assert_s(CryptoManager::searchExists(CryptoManager::token(key,
                                                              word1),
                                         CryptoManager::encryptSWP(key,
                                                                   vec4)),
             "incorrect found flag in vec4");

    LOG(test) << "   -- OK";



}

void
TestCrypto::run(const TestConfig &tc, int argc, char ** argv)
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
    cerr << "Testing PBKDF2" << endl;
    testPBKDF2();
    cerr << "Done! All crypto tests passed." << endl;
}
