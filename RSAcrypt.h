/*
 * File: AEScrypt.h
 * 
 * Dependencies: N/A
 * 
 * Purpose: Header file for RSA class 
 * 
 * Authors: Colin Moore, Connor Spangler
 * 
 * Last modified: 28 NOV 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */

#ifndef RSACRYPT_H
#define RSACRYPT_H

#include <string>

class RSAdata;

class RSAcrypt
{
	private:
		RSAdata *RSA;
	public:
		RSAcrypt(const char* pubKey, const char* prvKey);
		RSAcrypt();
		~RSAcrypt();
		char* encrypt(char* data);
		char* decrypt(char* data);
		void genKeys();
		void setKeys(const char* pubKey, const char* prvKey);
		const char* getPubKey();
		const char* getPrvKey();
};

#endif
