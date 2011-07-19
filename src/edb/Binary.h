/*
 * Binary.h
 *
 * A library for binary numbers with functions useful to crypto protocols.
 *
 */

#ifndef BINARY_H_
#define BINARY_H_

#include <string>
#include "stdlib.h"
#include "string.h"
#include "math.h"

#include <list>

using namespace std;

class Binary {

public:
	Binary();

	//allocates len bytes
	Binary(unsigned int len);

	//allocates len bytes and copies
	Binary(unsigned int len, unsigned char * val);

	//performs deep copy
	Binary(const Binary & b);

	//constructs a Binary as a concatenation of more binaries
	Binary(const list<Binary> & ciphs);

	//does not free "this" deeply, use Free for this purpose
	~Binary();
	void Free(); //deallocates any memory taken by this




	unsigned int len;
	unsigned char * content;

	//concatenates this and b
	Binary operator+(const Binary & b) const;

	//bitwise xor-s between this and b, shorter one padded with zero at the end
	Binary operator ^ (const Binary & b) const;

	//returns true if this and b are equal in value
	bool operator==(const Binary & b) const;

	//returns a Binary that consists of "no" bytes from "this" from position "pos"
	//requires: this.len <= pos + no
	Binary subbinary(unsigned int pos, unsigned int no) const;


	/* Conversions */

	string toString() const;

	/* If no_bytes is specified (nonnegative), the Binary created will be forced to no_bytes
	 * by adding leading zeros; if no_bytes < bytes needed, an error is thrown
	 */
	static Binary toBinary(unsigned long val, int no_bytes = -1);
	unsigned int toUInt();
	static Binary toBinary(string val);



	//splits the given longbin Binary into pieces each of length len
	// len must divide the length of longbin
	list<Binary> * split(unsigned int len) const;
};




#endif /* BINARY_H_ */
