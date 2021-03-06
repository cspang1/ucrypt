/*
 * File: AEScrypt.h
 * 
 * Dependencies: N/A
 * 
 * Purpose: Provides support for the Base64 encoding standard 
 * 
 * Authors: Mariah Arndorfer, Connor Spangler
 * 
 * Last modified: 6 DEC 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */

#include <string>
#include <iostream>
#include "B64coder.h"

 /*
  * Class: B64data
  *
  * Purpose: contains the private members of class B64coder
  */
class B64data
{
	public:
		// B64 constants
		static const unsigned int CYPHER_SIZE = 65;
		const char cypher[CYPHER_SIZE] = 
		{
			'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q',
			'R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h',
			'i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y',
			'z','0','1','2','3','4','5','6','7','8','9','+','/','='
		};
		// 6 bit binary values
		int Binary6[6] = {32,16,8,4,2,1};
		// 8 bit binary values
		int Binary8[8] = {128,64,32,16,8,4,2,1};
		// B64data Functions
		int cypherIndex(char value);
        	char cypherLookup(int index);
        	std::vector<int> Bit6ToDec(std::string bin8);
        	std::vector<int> BinaryToKey(std::string bin6);
};

 /*
  * Constructor: B64coder()
  *
  * Purpose: Generate B64coder object
  *
  * Arguments: None
  */
B64coder::B64coder()
{
	B64 = new B64data;
}

 /*
  * Constructor: ~B64coder()
  *
  * Purpose: Deallocate B64coder and B64data memory
  *
  * Arguments: None
  */
B64coder::~B64coder()
{
	delete B64;
}

 /*
  * Constructor: char* B64coder::encode(char* key)
  *
  * Purpose: Use Base64 to encode data
  *
  * Arguments: char* key = starting address of a char array
  *
  * Returns: Result of encoded data
  */
char* B64coder::encode(char* key)
{
	std::string fullBinary;
        fullBinary = To8Binary(key);
        std::vector<int> Decimal((fullBinary.size() + 4)/6);
        Decimal = B64->Bit6ToDec(fullBinary);
        int finalSize = Decimal.size();
        while (finalSize % 4 != 0)
        {
                finalSize++;
        }
        char* fkptr = new char[Decimal.size()];
        for (int x = 0; x < finalSize; x++)
        {
                if( x < Decimal.size() )
                {
                        fkptr[x] = B64->cypherLookup(Decimal[x]);
                }else {
                        fkptr[x] = '=';
                }
        }
        return fkptr;
}

 /*
  * Constructor: char* B64coder::decode(char* key)
  *
  * Purpose: Use Base64 to decode data
  *
  * Arguments: char* key = starting address of a char array
  *
  * Returns: Result of decoded data
  */
char* B64coder::decode(char* key)
{
	std::vector<int> DecVal = KeyToDecimal(key);
        std::string binary6 = DecToBin6(DecVal);
        std::vector<int> finalKeyDec = B64->BinaryToKey(binary6);
        char* fkptr = new char[finalKeyDec.size()];
        for (int i = 0; i < finalKeyDec.size(); i++)
        {
                fkptr[i] = finalKeyDec[i];
        }
        return fkptr;
}

//--------------Functions for encoding-------------------------------
 /*
  * Constructor: std::string B64coder::To8Binary(char* key)
  *
  * Purpose: Converts the data to decimal, then to an 8 bit binary string
  *
  * Arguments: char* key = starting address of a char array
  *
  * Returns: String of 8 bit binary
  */
std::string B64coder::To8Binary(char* key)
{
        std::string binary8;
        std::string temp;
        char *ptr = key;
        int decimal;
        while(*ptr)
        {
                decimal = *ptr;
                temp = DecimalToBinary(decimal);
                while( temp.length() < 8 )
                {
                        temp = "0" + temp;
                }
                binary8 += temp;
                ptr++;
        }
        return binary8;
}

 /*
  * Constructor: std::string B64coder::DecimalToBinary(int number)
  *
  * Purpose: Converts a decimal number to binary
  *
  * Arguments: int number = a decimal number
  *
  * Returns: String of the binary representation of a decimal number
  */
std::string B64coder::DecimalToBinary(int number)
{
        if (number == 0) return "0";
        if (number == 1) return "1";

        if ( number % 2 == 0 )
        {
                return DecimalToBinary(number/2) + "0";
        }else{
                return DecimalToBinary(number/2) + "1";
        }
}

//--------------Functions for decoding-------------------------------
 /*
  * Constructor: std::vector<int> B64coder::KeyToDecimal(char* key)
  *
  * Purpose: Finds the decimal value for each char in key with respect to cypher
  *
  * Arguments: char* key = starting address of a char array
  *
  * Returns: std::vector<int> = each int corresponds to a single values decimal value
  */
std::vector<int> B64coder::KeyToDecimal(char* key)
{
        int length = findSize(key);
        std::vector<int> DecCy(length);
        int loc;
        for ( int i = 0; i < length; i++ )
        {
                loc = B64->cypherIndex(*key);
                DecCy[i] = loc;
                key++;
        }
        return DecCy;
}

 /*
  * Constructor: int B64coder::findSize(char* key)
  *
  * Purpose: Finds the size without padding "=" of the char arrayed referenced by key 
  *
  * Arguments: char* key = starting address of a char array
  *
  * Returns: int = the char array size
  */
int B64coder::findSize(char* key)
{
        int size = 0;
        while( *key )
        {
                if ( *key == '=' )
                {
                        break;
                }
                size++;
                key++;
        }
        return size;
}

 /*
  * Constructor: std::string B64coder::DecToBin6(std::vector<int> decimals)
  *
  * Purpose: Converts each int in the vector to 6 bit binary
  *
  * Arguments: std::vector<int> decimals
  *
  * Returns: std::string = concatenated string of each 6bit binary value
  */
std::string B64coder::DecToBin6(std::vector<int> decimals)
{
        std::string binary6;
        std::string temp;
        for (int i = 0; i < decimals.size(); i++)
        {
                temp = DecimalToBinary(decimals[i]);
                while( temp.length() < 6 )
                {
                        temp = "0" + temp;
                }
                binary6 += temp;
        }
        return binary6;
}

//--------------Functions for B64data--------------------------------
 /*
  * Constructor: int B64data::cypherIndex(char value)
  *
  * Purpose: Use cypher to find the index of the inputted value
  *
  * Arguments: char value = value being searched for in cypher
  *
  * Returns: int = the index value
  */
int B64data::cypherIndex(char value)
{
        int index = 0;
        for ( int i = 0; i < CYPHER_SIZE; i++, index++ )
        {
                if( cypher[i] == value )
                {
                        return index;
                }
        }
        return index;
}

 /*
  * Constructor: char B64data::cypherLookup(int index)
  *
  * Purpose: Look up a value in cypher
  *
  * Arguments: int index = the index of the value being searched for in cypher
  *
  * Returns: The char result of the value found
  */
char B64data::cypherLookup(int index)
{
        return cypher[index];
}

 /*
  * Constructor: std::vector<int> B64data::Bit6ToDec(std::string bin8)
  *
  * Purpose: Convert from 8 bit binary to 6 bit binary, then convert to decimal
  *
  * Arguments: std::string bin8 = string of 8 bit binary values
  *
  * Returns: vector<int> of the decimal values
  */
std::vector<int> B64data::Bit6ToDec(std::string bin8)
{
        while (bin8.length() % 6 != 0)
        {
                bin8 += "0";
        }
        int sum = 0;
        int length = bin8.length()/6;
        std::vector<int> decimal(length);
        int count = 0;
        int j = 0;
        for (int i = 0; i < (bin8.length() + 1); i++, j++)
        {
                if (j == 6)
                {
                        decimal[count] = sum;
                        sum = 0;
                        j = 0;
                        count++;
                }
                if (bin8[i] == '1')
                {
                        sum += Binary6[j];
                }
        }
        return decimal;
}

 /*
  * Constructor: vector<int> B64data::BinaryToKey(std::string bin6)
  *
  * Purpose: Convert from 6 bit binary to 8 bit binary, then to decimal
  *
  * Arguments: std::string bin6 = string of 6 bit binary values
  *
  * Returns: vector<int> of decimal values
  */
std::vector<int> B64data::BinaryToKey(std::string bin6)
{
        while( bin6.length() % 8 != 0 )
        {
                bin6.erase(bin6.length()-1);
        }
        int length = bin6.length()/8;
        std::vector<int> decimal(length);
        int count = 0;
        int j = 0;
        int sum = 0;
        for (int i = 0; i < (bin6.length() + 1); i++, j++)
        {
                if (j == 8)
                {
                        decimal[count] = sum;
                        sum = 0;
                        j = 0;
                        count++;
                }
                if (bin6[i] == '1')
                {
                        sum += Binary8[j];
                }
        }
        return decimal;
}
