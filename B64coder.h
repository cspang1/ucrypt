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
		std::string DecimalToBinary(int number);
                std::string To8Binary(char* key);
                // Functions for decoding
                std::vector<int> KeyToDecimal(char* key);
                int findSize(char* key);
                std::string DecToBin6(std::vector<int> decimals);
};

#endif
