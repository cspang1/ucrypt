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
#include <sstream>
#include "RSAcrypt.h"
#include "B64coder.h"
#include <gmp.h>

//temp
using namespace std;

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
	string key = RSA->pubKey;
	char *D;
	unsigned long int exp, temp;
	istringstream ss(key);
	mpz_t base;
	mpz_init(base);
	mpz_t mod;
 	mpz_t rop;
	mpz_init(rop);
	ss>>exp>>temp;
	mpz_init_set_ui(mod, temp);
	for(unsigned int x = 0; x < (16/sizeof(char)); x++)
	{
		*D = data[x];
		mpz_set_str( base, D, 10);
		mpz_powm_ui( rop, base, exp, mod);
		D = mpz_get_str( D, 10, rop);
		data[x] = *D; 
	}
	mpz_clear(base);
	mpz_clear(rop);
	mpz_clear(mod);	
	return data;
}

char* RSAcrypt::decrypt(char* data)
{
	string key = RSA->prvKey;
        char *D;
        unsigned long int exp, temp;
        istringstream ss(key);
        mpz_t base;
        mpz_init(base);
        mpz_t mod;
        mpz_t rop;
        mpz_init(rop);
        ss>>exp>>temp;
        mpz_init_set_ui(mod, temp);
        for(unsigned int x = 0; x < (16/sizeof(char)); x++)
        {
                *D = data[x];
                mpz_set_str( base, D, 10);
                mpz_powm_ui( rop, base, exp, mod);
                D = mpz_get_str( D, 10, rop);
                data[x] = *D;
        }
        mpz_clear(base);
        mpz_clear(rop);
        mpz_clear(mod);
        return data;
}

void RSAcrypt::setKeys(const char* pubKey, const char* prvKey)
{
	RSA->pubKey = pubKey;
	RSA->prvKey = prvKey;
}

void RSAcrypt::genKeys()
{
	RSA->pubKey = "NewPub Key";
	RSA->prvKey = "NewPrv Key";	
}	
	
const char* RSAcrypt::getPubKey()
{
	return RSA->pubKey;
}

const char* RSAcrypt::getPrvKey()
{
	return RSA->prvKey;
}
