/*
 * File: RSAcrypt.cpp
 * 
 * Dependencies: gmp library
 * 
 * Purpose: Provides support for the Rivest Shamir Adleman (RSA) algorithm
 * 
 * Authors: Colin Moore, Connor Spangler
 * 
 * Last modified: 19 DEC 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */

#include <string>
#include <cstring>
#include <sstream>
#include "RSAcrypt.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <inttypes.h>

//using namespace std;

unsigned long totient(unsigned long n);
void totient(mpz_t result, mpz_t n);
bool isPrime(const mpz_t n);
void generatePrime(mpz_t op);


/*
 * Class: RSAdata
 *
 * Purpose: Contains the private members of class RSAcrypt
 */

class RSAdata
{
	public:
		char* pubKey;// = new char [100];
		char* prvKey;// = new char [100];
};

/*
 * Constructor: RSAcrypt()
 *
 * Purpose: Generate blank RSAcrypt object
 *
 * Arguments: None
 */
RSAcrypt::RSAcrypt()
{
	RSA = new RSAdata;
	RSA->pubKey = new char [100];
	RSA->prvKey = new char [100];
}

/*
 * Constructor: RSAcrypt(const char* pubKey, const char* prvKey)
 * 
 * Purpose: Generate RSAcrypt object, setting private and public keys
 *
 * Arguments: valid public and private keys of the format 
 *            "Key CommonNumber" where CommonNumber is the product of two primes
 */
RSAcrypt::RSAcrypt( char* pubKey,  char* prvKey)
{
	RSA = new RSAdata;
	RSA->pubKey = pubKey;
	RSA->prvKey = prvKey;
}

/*
 * Destructor: ~RSAcrypt()
 *
 * Purpose: Deallocates RSAcrypt and RSAdata memory
 *
 * Arguments: None
 */
RSAcrypt::~RSAcrypt()
{
	delete RSA;

}

/*
 * Function: char* RSAcrypt::encrypt(char* data)
 *
 * Purpose: Encrypt the data by character
 *
 * Arguments: char* data = data to be encrypted
 *
 * Returns: char* containing encrypted data
 */
std::string RSAcrypt::encrypt(std::string data)
{
	std::string key = RSA->pubKey;
	unsigned long int exp, temp;
	std::istringstream ss(key);
	mpz_t base;
	mpz_init(base);
	mpz_t mod;
	mpz_init(mod);
 	mpz_t rop;
	mpz_init(rop);
	ss>>exp>>temp;
	mpz_set_ui(mod, temp);
	unsigned int fox;
	char *P = new char [12], *D = new char [1], *iop = new char [data.size()];
	for (unsigned int rIOP = 0; rIOP<data.size(); rIOP++) {
		iop[rIOP] = '\0';
	}

	for (unsigned int cpy = 0; cpy<data.size(); cpy++) {

		iop[cpy] = data[cpy];
	}
	
	unsigned int Madness[200];
	unsigned int mCount = 0;
	for(unsigned int x = 0; x<data.size()/*iop[x] !='\0'*/; x++) {
		*D = iop[x];
		fox = *D;
		sprintf(P, "%d" , fox);	
		mpz_set_str( base,  P, 10);
		mpz_powm_ui( rop, base, exp, mod);
		mpz_get_str( P, 10, rop);
		fox = atoi(P);
		*D =(char) fox;
		Madness[x] = fox;
		mCount++;
	}
	mpz_clear(base);
	mpz_clear(rop);
	mpz_clear(mod);
	unsigned int k = 0;
	delete [] iop;
	delete [] P;
	delete [] D;
	char * tAdder = new char [5000];
	for (int i = 0; i<5000; i++) {
		tAdder[i] = '\0';
	}
	while(k < mCount) {

		sprintf(tAdder, "%s %d", tAdder, Madness[k]);
		k++;
	}
	std::string Walmart = tAdder;
	delete [] tAdder;
	return Walmart;
}

/*
 * Function: std::string RSAcrypt::decrypt(std::string data)
 *
 * Purpose: decrypt data using current public and private keys
 *
 * Argumets: string data = data to be decrypted
 *
 * Returns: string containing decrypted data
 */
std::string RSAcrypt::decrypt(std::string data)
{
	std::string key = RSA->prvKey;
        unsigned long int exp, temp;
	std::istringstream ss(key);
	std::istringstream ss2(data);
	unsigned int Madness[200];
	unsigned int k = 0;
	while (!ss2.fail()) {
		ss2>>Madness[k];
		k++;
	}
	mpz_t base;
	mpz_init(base);
	mpz_t mod;
	mpz_init(mod);
 	mpz_t rop;
	mpz_init(rop);
	ss>>exp>>temp;
	mpz_set_ui(mod, temp);
	unsigned int fox;
	char *P = new char [12], *D = new char [1], *iop = new char [data.length()];
	for(unsigned int x = 0; x<(k-1); x++) {
		fox = Madness[x];
		sprintf(P, "%d" , fox);	
		mpz_set_str( base,  P, 10);
		mpz_powm_ui( rop, base, exp, mod);
		mpz_get_str( P, 10, rop);
		fox = atoi(P);
		*D =(char) fox;
		iop[x] = *D;

	}
	mpz_clear(base);
	mpz_clear(rop);
	mpz_clear(mod);
	std::string Walmart = iop;
	delete [] iop;
	delete [] P;
	delete [] D;
	return Walmart;
}

/*
 * Function: void RSAcrypt::setKeys(const char* pubKey, const char* prvKey)
 *
 * Purpose: Sets public and private keys for RSAcrypt class
 *
 * Arguments: valid public and private keys of the format 
 *            "Key CommonNumber" where CommonNumber is the product of two primes
 */
void RSAcrypt::setKeys( char* pubKey, char* prvKey)
{
	char* key = new char[100];
	char* key2 = new char[100];
	std::strcpy(key, pubKey);
	RSA->pubKey = key;
	std::strcpy(key2, prvKey);
	RSA->prvKey = key2;
}

/*
 * Function: void RSAcrypt::genKeys()
 *
 * Purpose:generates public and private keys for RSAcrypt class
 *
 * Arguments: None
 */
void RSAcrypt::genKeys()
{
	char R[100], q[100], p[100], prv[200], pub[200];
	unsigned int Tx = 11;
	mpz_t x;
	mpz_t y;
	mpz_t m;
	mpz_t k;
	mpz_init(x);
	mpz_init(y);
	mpz_init(m);
	mpz_init(k);
	generatePrime(x);
	generatePrime(y);
	mpz_mul(m,y,x); //multiplies y*x and stores it in m
	mpz_get_str(R, 10, m);
	totient(k, m);	
	mpz_set_ui(x,Tx);
	mpz_get_str(p, 10, x);
	for (unsigned int z = 1; mpz_cmp_ui(m,z) >  0; z++) {
		mpz_mul_ui(y,k,z);
		mpz_add_ui(y,y,1);
		mpz_mod(y,y,x);
		if (mpz_sgn(y) == 0) {
			mpz_mul_ui(y,k,z);
	                mpz_add_ui(y,y,1);
			mpz_divexact(y,y,x);
			if (mpz_cmp_ui(y,1) !=0)
				break;
		}
		//if Z*K +1 mod x = 0
		//q = (Z*k +1)/x
	}
	mpz_get_str(q,10,y);
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(m);
	mpz_clear(k);
	sprintf(pub, "%s %s", p, R);
	sprintf(prv, "%s %s", q, R);
	setKeys( pub, prv);
}	

/*
 * Function: const char* RSAcrypt::getPubKey()
 *
 * Purpose: Returns currently stored RSAcrypt public key
 *
 * Arguments: None
 *
 * Returns: const char* containing public key of the format
 * 	    "publickey CommonKey" where CommonKey is the product of two primes
 */	
const char* RSAcrypt::getPubKey()
{
	return RSA->pubKey;
}

/*
 * Function: const char* RSAcrypt::getPrvKey()
 *
 * Purpose: Returns currently stored RSAcrypt pprivate key
 *
 * Arguments: None
 *
 * Returns: const char* containing private key of the format
 *          "privatekey CommonKey" where CommonKey is the product of two primes
 */  
const char* RSAcrypt::getPrvKey()
{
	return RSA->prvKey;
}

/*
 * Function: generatePrime(mpz_t op)
 *
 * Prupose: generate a prime number and store it in op
 *
 * Arguments: mpz_t op = a gmp library data type to hold the prime
 */
void generatePrime(mpz_t op) {
        unsigned long n = 7;
	mpz_t rop;
	mpz_init (rop);
	gmp_randstate_t state;
        gmp_randinit_default(state); //initialize state
        mpz_urandomb(rop, state, n); //n using mp_bitcnt_t
        mpz_nextprime( op, rop);
	mpz_clear(rop);
	gmp_randclear(state);
}

/*
 * Function: bool isPrime(const mpz_t n)
 *
 * Purpose: return true if gmp library integer is prime
 *
 * Arguments: const mpz_t n = gmp library integer to be checked if prime
 *
 * Returns: true if prime false if not prime
 */
bool isPrime(const mpz_t n) {
        bool prime = false;
        int x = mpz_probab_prime_p( n, 25);
        if (x==2) {
                prime = true;
        }
        return prime;
}

/*
 * Function: totient( mpz_t result, mpz_t n)
 *
 * Prupose: returns euler's totient function falue for the given number
 *
 * Arguments: mpz_t result = the result of euler's totient function of mpz_t n
 * 	      mpz_t n = number to perform euler's totient function on.
 */
void totient(mpz_t result, mpz_t n) {
        unsigned long phi = 1, p, x;
        char str[] = "12344668890";
        x = strtoul( mpz_get_str( str, 10, n), NULL, 10);
        for (p = 2; p * p <= x; p += 2) {
                if (x % p == 0) {
                        phi *= p - 1;
                        x /= p;
                        while (x % p == 0) {
                                phi *= p;
                                x /= p;
                        }
                }

                if (p == 2)
                        p--;
        }

        if(x == 1)
                mpz_set_ui( result, phi);
        else
                mpz_set_ui( result, phi * (x - 1));
}

/*
 * Function: unsigned long totient( unsigned long n)
 *
 * Prupose: returns euler's totient function falue for the given number
 *
 * Arguments: unsigned long n = performs euler's totient function on this
 *
 * Returns: unsigned long containing the results
 */
unsigned long totient(unsigned long n) {

        unsigned long phi = 1, p;

        for (p = 2; p * p <= n; p += 2) {
                if (n % p == 0) {
                        phi *= p - 1;
                        n /= p;
                        while (n % p == 0) {
                                phi *= p;
                                n /= p;
                        }
                }
                if (p == 2)
                        p--;
        }

return (n == 1) ? phi : phi * (n - 1); //returns phi if n was prime, returns phi*(n-1) if n was not prime
}
