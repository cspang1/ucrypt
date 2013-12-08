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
#include <stdio.h>

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
	std::string key = RSA->pubKey;
	char *D;
	unsigned long int exp, temp;
	std::istringstream ss(key);
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
	std::string key = RSA->prvKey;
        char *D;
        unsigned long int exp, temp;
        std::istringstream ss(key);
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
	std::string pub, prv, R, q, p; //q is private p is public R is commonality
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
	mpz_mul(m,y,x); //multiplies y*x and stores it in x
	mpz_get_str(R, 10, m);

	totient(k, m);
	generatePrime(x);
	while (mpz_cmp(x , k) >= 0)
		generatePrime(x);	
	for (unsigned int z = 1; mpz_cmp_ui(k,z) < 0; z++)
	{
		mpz_mul_ui(y,k,z);
		mpz_add_ui(y,y,1);
		mpz_mod(y,y,x);
		if (mpz_sgn(y) == 0)
		{
			mpz_mul_ui(y,k,z);
	                mpz_add_ui(y,y,1);
			mpz_divexact(y,y,x)
		}
		//if Z*K +1 mod x = 0
		//q = (Z*k +1)/x
	}
	mpz_get_str(p,10,x);
	mpz_get_str(q,10,y);
	sprintf(pub, "%s %s", p, R);
	sprintf(prv, "%s %s", q, R);
	RSA->pubKey = pub;
	RSA->prvKey = prv;	
}	
	
const char* RSAcrypt::getPubKey()
{
	return RSA->pubKey;
}

const char* RSAcrypt::getPrvKey()
{
	return RSA->prvKey;
}

void generatePrime(mpz_t op) {
        unsigned long n = 64;
	mpz_t rop;
	mpz_t op;
	mpz_init (rop);
	mpz_init (op);
	gmp_randstate_t state;
        gmp_randinit_default(state); //initialize state
        mpz_urandomb(rop, state, n); //n using mp_bitcnt_t
        mpz_nextprime( op, rop);
	mpz_clear(rop);
	mpz_clear(op);
	gmp_randclear(state);
}

bool isPrime(const mpz_t n) {
        bool prime = false;
        int x = mpz_probab_prime_p( n, 25);
        if (x==2) {
                prime = true;
        }
        return prime;
}


void totient(mpz_t result, mpz_t n) {
        unsigned long phi = 1, p, x;
        char *str;
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
