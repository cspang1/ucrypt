/*
 * File: AEScrypt.h
 * 
 * Dependencies: N/A
 * 
 * Purpose: Provides support for the Base64 encoding standard 
 * 
 * Authors: Mariah Arndorfer, Connor Spangler
 * 
 * Last modified: 28 NOV 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */

#include <string>
#include <iostream>
#include "B64coder.h"

class B64data
{
	public:
		static const unsigned int CYPHER_SIZE = 65;
		const char cypher[CYPHER_SIZE] = 
		{
			'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q',
			'R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h',
			'i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y',
			'z','0','1','2','3','4','5','6','7','8','9','+','/','='
		};
};

B64coder::B64coder()
{
	B64 = new B64data;
}

B64coder::~B64coder()
{
	delete B64;
}

char* B64coder::encode(char* key)
{
	return key;
}

char* B64coder::decode(char* key)
{
	return key;
}
