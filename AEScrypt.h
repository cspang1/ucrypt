/*
 * File: AEScrypt.h
 *
 * Dependencies: N/A
 *
 * Purpose: Header file for AES class
 *
 * Authors: Connor Spangler
 *
 * Last modified: 2 DEC 13
 *
 * License: Creative Commons Attribution-NonCommercial 4.0 International License
 */

#ifndef AESCRYPT_H
#define AESCRYPT_H

#include <string>
#include <fstream>
#include <vector>

class AESdata;

// String-derived typedef for unsigned characters
typedef std::basic_string<unsigned char> ustring;

class AEScrypt
{
	private:
		AESdata *AES;
	public:
		AEScrypt(char* key);
		AEScrypt();
		~AEScrypt();
		ustring encrypt(std::string in);
		ustring encrypt(std::ifstream& in);
		ustring decrypt(ustring in);
		ustring decrypt(std::ifstream& in);
		std::string getKey();
		void setKey(char* key);
};

#endif
