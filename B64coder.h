/*
 * File: AEScrypt.h
 * 
 * Dependencies: N/A
 * 
 * Purpose: Header file for the Base64 class
 * 
 * Authors: Mariah Arndorfer, Connor Spangler
 * 
 * Last modified: 28 NOV 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */


#ifndef B64CODER_H
#define B64CODER_H

#include <string>

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
};

#endif
