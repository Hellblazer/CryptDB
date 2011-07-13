#include "OPE.h"


#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include "NTL/ZZ.h"

#include "NTL/RR.h"

#include "HGD.h"

//#include "AvlTree.h"
#include "params.h"

#include "util.h"

using namespace NTL;
using namespace std;



//TODO: use AVL tree for optimization and see if it improves the time
//TODO: sample HGD properly
// TO OPTIMIZE: to avoid conversion to ZZ and back, implement the math on uchar vectors

/***************
 *
 * The notation and algorithms here are from the paper "Order-preserving symmetric encryption" by Boldyreva et Al., 2009
 *
 */



typedef struct TreeNode {
	ZZ x, y, lowD, highD;
	ZZ MAX;
	//we can figure out R from y as follows: scan y for the first 0 from the right so y = C01111, lowR is C0000 and highR is C111
} TreeNode;

struct Distance: public binary_function<TreeNode, TreeNode, int>
{
	ZZ operator()(const TreeNode & a, const TreeNode & b) const
	{
		return a.x-b.y;
	}
};


struct Compare: public binary_function<TreeNode, TreeNode, bool>
{
	bool operator()(const TreeNode& a, const TreeNode& b) const
	{
		return a.x<b.x;
	}
};

uint64_t uint64FromZZ(ZZ val) {
	uint64_t res = 0;
	uint64_t mul = 1;
	while (val > 0) {
		res = res + mul*(to_int(val % 10));
		mul = mul * 10;
		val = val / 10;
	}
	return res;
}
uint32_t uint32FromZZ(ZZ val) {
	return (uint32_t) uint64FromZZ(val);
}

class OPEInternals {

public:

	unsigned int OPEPlaintextSize, OPECiphertextSize, OPE_KEY_SIZE;
	AES_KEY key;

	//AvlTree<TreeNode, Compare, Distance> cachingTree;


	ZZ SampleHGD(ZZ & lowD, ZZ & highD, ZZ & lowR, ZZ & highR, ZZ & y, ZZ & coins, unsigned int coinsLen) {
		ZZ whiteBalls = highD - lowD + 1;
		ZZ blackBalls = highR - lowR + 1 - whiteBalls;
		ZZ ballsPicked = y - lowR;
		//cerr << "white balls " << whiteBalls << " blackBalls " << blackBalls << " ballsPicked " << ballsPicked << "\n";
		myassert((whiteBalls > 0) && (blackBalls > 0) && (y >= lowR) && (y <= highR));
		unsigned int precision = NumBits(highR-lowR + 1) + 10;
		return lowD + HGD(ballsPicked, whiteBalls, blackBalls, coins, coinsLen, precision);

	}

	/* Returns a number that has a desired number of bits */
	ZZ TapeGen(ZZ & lowD, ZZ & highD, ZZ & y, unsigned int desiredNoBits) {
		unsigned char * lowDBytes = BytesFromZZ(lowD, OPEPlaintextSize/bitsPerByte);
		unsigned char * highDBytes = BytesFromZZ(highD, OPEPlaintextSize/bitsPerByte);
		unsigned char * yBytes = BytesFromZZ(y, OPECiphertextSize/bitsPerByte);

		unsigned char * concat = concatenate(lowDBytes, OPEPlaintextSize/bitsPerByte, highDBytes, OPEPlaintextSize/bitsPerByte, yBytes, OPECiphertextSize/bitsPerByte);

		int concatLen = (OPEPlaintextSize*2 + OPECiphertextSize)/bitsPerByte;
		//cerr << "concat before SHA "; myPrint(concat, (2*OPEPlaintextSize+OPECiphertextSize)/bitsPerByte); cerr << "\n";
		unsigned char * shaDigest = new unsigned char[SHA_DIGEST_LENGTH];
		SHA1(concat, concatLen, shaDigest);
		concat = adjustLen(shaDigest, SHA_DIGEST_LENGTH, AES_BLOCK_BITS/bitsPerByte);
		//cerr << "concat "; myPrint(concat, AES_BLOCK_BITS/bitsPerByte); cerr << "\n";
		unsigned char * seed = new unsigned char[AES_BLOCK_BITS/bitsPerByte];

		//myPrint(key.rd_key, 4*AES_MAXNR + 1); cerr << "\n";
		AES_encrypt(concat, seed, &key);

		unsigned int desiredBytes = desiredNoBits/bitsPerByte;


		if (AES_BLOCK_BITS >= desiredNoBits) {
			// cerr << "seed "; myPrint(seed, AES_BLOCK_BITS/bitsPerByte); cerr << "\n";
			return ZZFromBytes(adjustLen(seed, AES_BLOCK_BITS/bitsPerByte, desiredBytes), desiredBytes);
		}

		//need to generate more randomness using a PRG
		RAND_seed(seed, AES_BLOCK_BITS/bitsPerByte);
		unsigned char * buf = new unsigned char[desiredBytes];
		RAND_pseudo_bytes(buf, desiredBytes);
		//cerr << "seed " << seed << " buf " << buf << "\n";
		//cerr << " ============================================= \n";
		return ZZFromBytes(buf, desiredBytes);
	}


	ZZ encryptHelper(ZZ & lowD, ZZ & highD, ZZ & lowR, ZZ & highR, ZZ & m) {
		ZZ M = highD - lowD + 1;
		ZZ N = highR - lowR + 1;
		ZZ d = lowD - 1;
		ZZ r = lowR - 1;
		ZZ y = r + (N+1)/2;

		myassert(M > 0);

		//cerr << "running encrypt helper with D = [" << lowD << ", " << highD << "] R= " << lowR <<", " << highR << "]\n";

		ZZ coins;

		if (M == 1) {
			coins = TapeGen(lowD, highD, m, OPECiphertextSize);
			ZZ c = lowR + (coins % N);
			//cerr << "encryption is " << c << "\n";
			return c;
		}

		//D > 1
		coins = TapeGen(lowD, highD, y, OPEPlaintextSize);

		ZZ x = SampleHGD(lowD, highD, lowR, highR, y, coins, OPEPlaintextSize);

		//cerr << "E lD " << lowD << " hD " << highD << " lR " << lowR << " hR " << highR << " x " << x << " c " << coins << "\n";
		//cerr << "y " << y << "\n";
		if (m <= x) {
			lowD = d+1;
			highD = x;
			lowR = r+1;
			highR = y;
		} else {
			lowD = x+1;
			highD = d + M;
			lowR = y+1;
			highR = r+N;
		}

		return encryptHelper(lowD, highD, lowR, highR, m);
	}

	ZZ decryptHelper(ZZ & lowD, ZZ & highD, ZZ & lowR, ZZ & highR, ZZ & c) {
		ZZ M = highD - lowD + 1;
		ZZ N = highR - lowR + 1;
		ZZ d = lowD - 1;
		ZZ r = lowR - 1;
		ZZ y = r + (N+1)/2;

		//cerr << "running decrypt helper with D = [" << lowD << ", " << highD << "], R = [" << lowR << ", " << highR << "]\n";

		myassert(M > 0);

		ZZ coins, m;

		if (M == 1) {
			m = lowD;
			coins = TapeGen(lowD, highD, m, OPECiphertextSize);
			ZZ w = lowR + (coins % N);

			if (w==c) {
				return m;
			} else {
				myassert(false, "This value was not encrypted correctly");
			}

		}

		//M > 1
		coins = TapeGen(lowD, highD, y, OPEPlaintextSize);

		ZZ x = SampleHGD(lowD, highD, lowR, highR, y, coins, OPEPlaintextSize);

		if (c <= y) {
			lowD = d+1;
			highD = x;
			lowR = r+1;
			highR = y;
		} else {
			lowD = x+1;
			highD = d + M;
			lowR = y+1;
			highR = r+N;
		}

		return decryptHelper(lowD, highD, lowR, highR, c);
	}



};

OPE::OPE(unsigned char * key, unsigned int OPEPlaintextSize, unsigned int OPECiphertextSize) {

	iOPE = new OPEInternals;
	iOPE->OPEPlaintextSize = OPEPlaintextSize;
	iOPE->OPECiphertextSize = OPECiphertextSize;
	myassert(key != NULL);

	if (AES_set_encrypt_key(key, OPE_KEY_SIZE, &iOPE->key) <0) {
		myassert(false, "problem with AES set encrypt ");
	}
}

// TODO: should these be ZZ to avoid the conversion once again == decrease nr of conversions!
/**
 * requires: size of plaintext is OPEPlaintextSize
 */
unsigned char * OPE::encrypt(unsigned char * plaintext) {



	//transford plaintext to ZZ
	ZZ m = ZZFromBytes(plaintext, iOPE->OPEPlaintextSize/bitsPerByte);

	//cerr  << "TO ENCRYPT: " << m << "\n";

	ZZ lowD = to_ZZ(0);
	ZZ highD = LeftShift(to_ZZ(1), iOPE->OPEPlaintextSize) - 1;
	ZZ lowR = to_ZZ(0);
	ZZ highR = LeftShift(to_ZZ(1), iOPE->OPECiphertextSize) - 1;

	ZZ res = iOPE->encryptHelper(lowD, highD, lowR, highR, m);

	return BytesFromZZ(res, iOPE->OPECiphertextSize/bitsPerByte);
}


uint64_t OPE::encrypt(uint32_t plaintext) {

	//transform plaintext to ZZ
	ZZ m;
	m = plaintext;

	ZZ lowD = to_ZZ(0);
	ZZ highD = LeftShift(to_ZZ(1), iOPE->OPEPlaintextSize) - 1;
	ZZ lowR = to_ZZ(0);
	ZZ highR = LeftShift(to_ZZ(1), iOPE->OPECiphertextSize) - 1;

	ZZ res = iOPE->encryptHelper(lowD, highD, lowR, highR, m);
	return uint64FromZZ(res);
}

uint32_t OPE::decrypt(uint64_t ciphertext) {

	//transform plaintext to ZZ
	ZZ c = UInt64_tToZZ(ciphertext);

	ZZ lowD = to_ZZ(0);
	ZZ highD = LeftShift(to_ZZ(1), iOPE->OPEPlaintextSize) - 1;
	ZZ lowR = to_ZZ(0);
	ZZ highR = LeftShift(to_ZZ(1), iOPE->OPECiphertextSize) - 1;

	ZZ res = iOPE->decryptHelper(lowD, highD, lowR, highR, c);

	return uint32FromZZ(res);
}


/**
 * requires: size of ciphertext is OPECiphertextSize
 */
unsigned char * OPE::decrypt(unsigned char * ciphertext) {

	//transform plaintext to ZZ
	ZZ c = ZZFromBytes(ciphertext, iOPE->OPECiphertextSize/bitsPerByte);

	//cerr << "TO DECRYPT " << c << "\n";

	ZZ lowD = to_ZZ(0);
	ZZ highD = LeftShift(to_ZZ(1), iOPE->OPEPlaintextSize) - 1;
	ZZ lowR = to_ZZ(0);
	ZZ highR = LeftShift(to_ZZ(1), iOPE->OPECiphertextSize) - 1;

	ZZ res = iOPE->decryptHelper(lowD, highD, lowR, highR, c);

	return BytesFromZZ(res, iOPE->OPEPlaintextSize/bitsPerByte);

}





