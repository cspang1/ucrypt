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
		RSAcrypt( char* pubKey,  char* prvKey);
		RSAcrypt();
		~RSAcrypt();
		std::string encrypt(std::string data);
		std::string decrypt(std::string data);
		void genKeys();
		void setKeys( char* pubKey, char* prvKey);
		const char* getPubKey();
		const char* getPrvKey();
};

#endif
