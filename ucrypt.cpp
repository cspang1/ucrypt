/*
 * File: ucrypt.cpp
 * 
 * Dependencies: AEScrypt, RSAcrypt, hashlib++
 * 
 * Purpose: Provides a user interface for using RSA and AES cryptographical classes
 * 
 * Authors: Connor Spangler
 * 
 * Last modified: 2 DEC 13
 * 
 * License: Creative Commons Attribution-NonCommercial 4.0 International License 
 */

// Includes
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <vector>
#include <hashlibpp.h>
#include "AEScrypt.h"
#include "RSAcrypt.h"

// Use standard namespace
using namespace std;

// Function forward declarations
void dispHelp();
int throwError(int e);
vector<int> validKey(char * key);
bool genRSAkeys();
bool keyCheck();
void dispSpecs();

// Instantiate AES and RSA key sizes in bytes
static const unsigned int AES_KEY_SIZE = 16/sizeof(char);
static const unsigned int RSA_KEY_SIZE = 128/sizeof(char);
// Instantiate RSA key containers
static const char* RSApubKey = new char[RSA_KEY_SIZE];
static const char* RSAprvKey = new char[RSA_KEY_SIZE];
// Instantiate RSA class
static RSAcrypt RSA;

// Main function
int main(int argc, char * argv[])
{
	// Instantiate SHA256 hash wrapper
	hashwrapper *hasher = new sha256wrapper();
	// Instantiate key containers
	string hash;
	char* tempKey = new char[AES_KEY_SIZE];
	char* key = new char[AES_KEY_SIZE];
	char* RSAkey = new char[RSA_KEY_SIZE];
	const char* encryptedKey = new char[RSA_KEY_SIZE];
	// Instantiate directory and filename strings
	string ddest = "Decrypted/";
	string edest = "Encrypted/";
	string path;
	string keytxt = "Key.txt";
	string keyPath(argv[argc-1]);
	// Instantiate configuration vector
	vector<int> config(2,0);
	// Instantiate booleans for command line parameters
	bool nrsa = false, sti = false, dec = false, rsa = false, del = false, dkey = false;
	// Instantiate ints for dup and optget
	int opt = 0, devNull = open("/dev/null", O_WRONLY), stout = dup(1);
	// Get command line parameters
	while((opt = getopt(argc, argv, "nqhrsdxk")) != EOF)
	{
		switch(opt)
		{
			case 'n':
				// New RSA keys
				nrsa = true;
			break;
			case 'q':
				// Suppress standard output
				dup2(devNull, STDOUT_FILENO);
			break;
			case 'h':
				// Display help
				dup2(stout, 1);
				close(stout);
				dispHelp();
				return 0;
			break;
			case 'r':
				// RSA encrypt AES key
				rsa = true;
			break;
			case 's':
				// Use standard input for data
				sti = true;
			break;
			case 'd':
				// AES descrypt data
				dec = true;
			break;
			case 'x':
				// Delete infile after encryption/decryption
				del = true;
			break;
			case 'k':
				// RSA decrypt AES keyfile
				dkey = true;
			break;
			default:
				// Parameter not found
				return throwError(-3);
			break;
		}
	}
	if(optind == argc)
		return throwError(-9);
	if(sti && (argc - optind > 1))
		return throwError(-10);
	// If RSA is being used, get public and private keys
	if(dkey || rsa)
	{
		// Check that the RSA keys exist
		if(!keyCheck())
		{
			// If the AES key doesn't need to be RSA decrypted
			if(!dkey)
			{
				if(!genRSAkeys())
					return throwError(-7);
			}
			// If the keys don't exist then the keyfile can't be decrypted
			else 
				return throwError(-11);
		}
		char* tempPubKey = new char[RSA_KEY_SIZE];
		char* tempPrvKey = new char[RSA_KEY_SIZE];
		ifstream RSApubi("RSA/RSAPub.txt"); // Change to xml in implementation
		RSApubi.getline(tempPubKey, 256);
		ifstream RSAprvi("RSA/RSAPrv.txt"); // Change to xml in implementation
		RSAprvi.getline(tempPrvKey, 256);
		RSApubKey = tempPubKey;
		RSAprvKey = tempPrvKey;
		RSA.setKeys(RSApubKey, RSAprvKey);
		RSApubi.close();
		RSAprvi.close();
	}
	// Read AES key from args if it's not going to be RSA decrypted
	if(!dkey)
		hash = hasher->getHashFromString(keyPath);
	// Read AES key from file otherwise
	else
	{
		ifstream keyFile(keyPath);
		if(!keyFile.is_open())
			return throwError(-1);
		keyFile.getline(RSAkey, 256);
		tempKey = RSA.decrypt(RSAkey);
		string temp(tempKey);
		hash = hasher->getHashFromString(temp.c_str());		
	}
	tempKey = (char*)hash.c_str();
	// Concetenate hash to 16 bytes
	for(unsigned int x = 0; x < AES_KEY_SIZE; x++)
		key[x] = tempKey[x];	
	// Generate configuration vector and analyze
	config = validKey(key);
	if(config[0])
		return config[1];
	// Create AEScrypt object for AES encryption
	AEScrypt AES(key);
	// If standard input is not being used
	if(!sti)
	{
		// Check if no key was provided or if it is the same as the infile name
		if(argc-1 == optind)
			return throwError(-8);
		// Iterate through files and check all are valid
		for(int x = optind; x < argc-1; x++)
		{
			ifstream in(argv[x]);
			if(!in.is_open())
			{
				cout << argv[x] << endl;
				return throwError(-1);
			}
			in.close();
		}
		// Iterate through files
		for(int x = optind; x < argc-1; x++)
		{
			ifstream in(argv[x]);
			ofstream out;
			ustring result;
			// AES encrypt file stream
			if(!dec)
			{
				path = edest + argv[x];
				out.open(path.c_str());
				result = AES.encrypt(in);
			}
			// AES decrypt file stream
			else
			{
				path = ddest + argv[x];
				out.open(path.c_str());
				result = AES.decrypt(in);
			}
			for(unsigned int ln = 0; ln < result.length(); ln++)
				out << (unsigned char)result.at(ln);
			out.close();
			// Delete infile
			if(del)
				if(remove(argv[x]))
					throwError(-6);
			in.close();
		}
	}
	// Read data from standard input
	else
	{
		string in;
		ofstream out;
		// Open file stream to Encrypted
		path = edest + "stdin.txt";
		out.open(path.c_str(), ios::binary);
		// Retrieve data via cin
		getline(cin, in);
		ustring result;
		// AES encrypt data
		result = AES.encrypt(in);
		for(unsigned int ln = 0; ln < result.length(); ln++)
		out << (unsigned char)result.at(ln);
		out.close();
	}
	// Generate new RSA keys
	if(nrsa)
		if(!genRSAkeys())
			return throwError(-7);
	// RSA encrypt AES key
	if(rsa)
	{
		encryptedKey = RSA.encrypt(key);
		ofstream out(keytxt.c_str());
		out << encryptedKey;
		out.close();
	}
	dispSpecs();
	return 0;
}
 
 /*
  * Function: bool genRSAkeys()
  * 
  * Purpose: Use RSAcrypt object to generate RSA private and public key files
  * 
  * Arguments: None
  * 
  * Returns: A boolean value indicating whether the keys were successfully generated
  */
bool genRSAkeys()
{
	RSA.genKeys();
	RSApubKey = RSA.getPubKey();
	RSAprvKey = RSA.getPrvKey();
	ofstream RSApubo("RSA/RSAPub.txt"); // Change to xml in implementation
	ofstream RSAprvo("RSA/RSAPrv.txt"); // Change to xml in implementation
	if(!RSApubo.is_open() || !RSAprvo.is_open())
		return false;
	RSApubo << RSApubKey;
	RSAprvo << RSAprvKey;
	RSApubo.close();
	RSAprvo.close();
	return true;
}

 /*
  * Function: bool keyCheck()
  * 
  * Purpose: Check whether the RSA public and private key files exist
  * 
  * Arguments: None
  * 
  * Returns: A boolean value indicating whether the key files were found
  */
bool keyCheck()
{
	ifstream pubin("RSA/RSAPub.txt"); // Change to xml in implementation
	ifstream prvin("RSA/RSAPrv.txt"); // Change to xml in implementation
	if(!pubin.is_open() || !prvin.is_open())
		return false;
	return true;
}

 /*
  * Function: bool validKey(char* key)
  * 
  * Purpose: Check whether the key is a filename or not long enough
  * 
  * Arguments: char * key = AES key
  * 
  * Returns: A bool representing whether the key was good
  */
vector<int> validKey(char* key)
{
	vector<int> result(2,0);
	ifstream in(key);
	if(in.is_open())
	{
		result[0] = 1;
		result[1] = throwError(-4);
	}
	unsigned int x;
	for(x = 0;key[x] != 0;x++){}
	if(x > AES_KEY_SIZE)
	{
		result[0] = 1;
		result[1] = throwError(-2);
	}
	return result;
}

 /*
  * Function: int throwError(int e)
  * 
  * Purpose: Display an error/warning message based upon the error code e
  * 
  * Arguments: int e = error code
  * 
  * Returns: The original error code supplied
  */
int throwError(int e)
{
	switch(e)
	{
		case -1:
		cerr << "Error: File not found or is corrupted." << endl;
		break;
		case -2:
		cerr << "Error: Key length must be <= 16 bytes." << endl;
		break;
		case -3:
		// Option errors handled by getopt
		break;
		case -4:
		cerr << "Error: Key must be provided and can not be the same as file name." << endl;
		break;
		case -6:
		cerr << "Warning: File deletion failed." << endl;
		break;
		case -7:
		cerr << "Error: Failed to create RSA key outfiles, make sure you have directory write permissions." << endl;
		break;
		case -8:
		cerr << "Error: A valid input file must be provided if -s is not used." << endl;
		break;
		case -9:
		cerr << "Error: Too few arguments. Use -h for usage." << endl;
		break;
		case -10:
		cerr << "Error: Too many arguments. Use -h for usage." << endl;
		break;
		case -11:
		cerr << "Error: No RSA keys exist. Key is undecryptable." << endl;
		break;
		default:
		break;
	}
	return e;
}

void dispSpecs()
{
	cout << "SPECS" << endl;
}

 /*
  * Function: void dispHelp()
  * 
  * Purpose: Display usage information for ucrypt when -h is used
  * 
  * Arguments: None
  * 
  * Returns: Nothing
  */
void dispHelp()
{
	cout << endl << "Usage: ucrypt [OPTION] ... [FILE] ... KEY" << endl;
	cout << "Encrypt or decrypt FILE or standard input using KEY." << endl;
	cout << "ucrypt results are stored in the local 'Encrypted' or 'Decrypted' folder." << endl;
	cout << "If standard input is used, FILE will be the desired output file name." << endl;
	cout << "RSA key pair will be generated automatically if none exists." << endl;
	cout << "The AES key will be stored in 'Encrypted/FILEKey.xml' if -r is used." << endl;
	cout << "The RSA key pair will be stored in'RSA/RSAPub' and 'RSA/RSAPrv'." << endl;
	cout << "If RSA key decrypt is used, KEY will be a file containing the AES key." << endl;
	cout << "Example: AEScrypt -q -e secrets.txt password123" << endl << endl;
	cout << "Cryptographical control:" << endl;
	cout << "  -d		Decrypt AES encrypted FILE" << endl;
	cout << "  -r		RSA encrypt AES key from command line" << endl;
	cout << "  -k		RSA decrypt AES key from file" << endl;
	cout << "  -n		Generate new RSA key pair" << endl << endl;
	cout << "Output control:" << endl;
	cout << "  -q		Suppress standard output" << endl;
	cout << "  -s		Use standard in for input" << endl;
	cout << "  -h		Print help info" << endl << endl;
	cout << "File control:" << endl;
	cout << "  -x		Delete original file after encryption/decryption" << endl << endl;
}
