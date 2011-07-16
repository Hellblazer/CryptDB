/*
 * TestCrypto
 * -- tests crypto work; migrated from test.cc
 *
 *
 */

#include "TestCrypto.h"

TestCrypto::TestCrypto() {}

TestCrypto::~TestCrypto() {}

void
testOPE() {

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

  assert_s(plaintext_s == decryption, "OPE test failed: decryption does not match plaintext");
  assert_s(plaintext_s.compare(ciphertext) != 0, "OPE test failed: ciphertext is the same as plaintext");
}

void
testHDG() {
  unsigned int len = 16;     //bytes
  unsigned int bitsPrecision = len * bitsPerByte + 10;
  ZZ K = ZZFromString(randomBytes(len));
  ZZ N1 = ZZFromString(randomBytes(len));
  ZZ N2 = ZZFromString(randomBytes(len));
  ZZ SEED = ZZFromString(randomBytes(len));

  ZZ sample = HGD(K, N1, N2, SEED, len*bitsPerByte, bitsPrecision);

  cerr << "N1 is "; myPrint(BytesFromZZ(N1,len), len); cerr << "\n";
  cerr << "N2 is "; myPrint(BytesFromZZ(N2,len), len); cerr << "\n";
  cerr << "K is "; myPrint(BytesFromZZ(K, len), len); cerr << "\n";
  cerr << "HGD sample is ";
  myPrint(BytesFromZZ(sample, len), len); cerr << "\n";
}

void
testPKCS() {
  
}

void
TestCrypto::run(int argc, char ** argv) {
  cerr << "TESTING CRYPTO" << endl;
  cerr << "Testing OPE..." << endl;
  testOPE();
  cerr << "Testing HDG..." << endl;
  testHDG();
  cerr << "Testing PKCS..." << endl;
  testPKCS();
  cerr << "Done! All crypto tests passed." << endl;
}
