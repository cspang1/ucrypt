/*
 * File: B64coder.h
 * 
 * Dependencies: N/A
 * 
 * Purpose: Header file for the Base64 class
 * 
 * Authors: Mariah Arndorfer, Connor Spangler
 * 
 * Last modified: 6 DEC 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */


#ifndef B64CODER_H
#define B64CODER_H

#include <string>
#include <vector>

class B64data;

class B64coder
{
	private:
		B64data *B64;
	public:
		B64coder();
		~B64coder();
		char* encode(char* key);
		char* decode(char* key);
		// Functions for encoding
		string DecimalToBinary(int number);
                string To8Binary(char* key);
                vector<int> Bit6ToDec(string bin8);
                // Functions for decoding
                vector<int> KeyToDecimal(char* key);
                int cypherIndex(char key);
                int findSize(char* key);
                string DecToBin6(vector<int> decimals);
                vector<int> BinaryToKey(string bin6);
};

#endif
