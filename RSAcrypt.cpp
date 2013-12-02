/*
 * File: RSAcrypt.cpp
 * 
 * Dependencies: B64coder
 * 
 * Purpose: Provides support for the Rivest Shamir Adleman (RSA) algorithm
 * 
 * Authors: Colin Moore, Connor Spangler
 * 
 * Last modified: 28 NOV 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */

#include <string>
#include "RSAcrypt.h"
#include "B64coder.h"

class RSAdata
{
	public:
		const char* pubKey;
		const char* prvKey;
		B64coder B64;
};

RSAcrypt::RSAcrypt()
{
	RSA = new RSAdata;
}

RSAcrypt::RSAcrypt(const char* pubKey, const char* prvKey)
{
	RSA = new RSAdata;
	RSA->pubKey = pubKey;
	RSA->prvKey = prvKey;
}

RSAcrypt::~RSAcrypt()
{
	delete RSA;
}

char* RSAcrypt::encrypt(char* data)
{
	return data;
}

char* RSAcrypt::decrypt(char* data)
{
	return data;
}

void RSAcrypt::setKeys(const char* pubKey, const char* prvKey)
{
	RSA->pubKey = pubKey;
	RSA->prvKey = prvKey;
}

void RSAcrypt::genKeys()
{
	RSA->pubKey = "NewPubKey";
	RSA->prvKey = "NewPrvKey";	
}	
	
const char* RSAcrypt::getPubKey()
{
	return RSA->pubKey;
}

const char* RSAcrypt::getPrvKey()
{
	return RSA->prvKey;
}
