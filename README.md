AES/RSA Encrypter/Decrypter (ucrypt)

contributors: cspang1, colinj5, mdorfer
url: https://github.com/cspang1/ucrypt

required libraries: Hashlib++ (http://hashlib2plus.sourceforge.net/), GNU GMP (http://gmplib.org/)

Ucrypt is a command line program which allows the user to encrypt and decrypt files as well as data entered via standard in using the 128 bit version of the Advanced Encryption Standard (AES) algorithm. The key which is used to encrypt/decrypt a file can then be encrypted/decrypted using the Rivest Shamir Adleman (RSA) algorithm. The public and private RSA keys which are generated will be encrypted using the Base64 encryption scheme. Together, RSA and AES represent the two most widely used and most secure cryptographical algorithms to date.

For ucrypt usage help, use the -h command line flag: ./ucrypt -h

Usage information is included here as well:

Usage: ucrypt [OPTION] ... [FILE] ... KEY
Encrypt or decrypt FILE or standard input using KEY.
ucrypt results are stored in the local 'Encrypted' or 'Decrypted' folder.
If standard input is used, FILE will be the desired output file name.
RSA key pair will be generated automatically if none exists.
The AES key will be stored in 'Encrypted/FILEKey.xml' if -r is used.
The RSA key pair will be stored in'RSA/RSAPub' and 'RSA/RSAPrv'.
If RSA key decrypt is used, KEY will be a file containing the AES key.
Example: AEScrypt -q -d secrets.txt password123

Cryptographical control:
 -d                Decrypt AES encrypted FILE
 -r                RSA encrypt AES key from command line
 -k                RSA decrypt AES key from file
 -n                Generate new RSA key pair
Output control:
 -q                Suppress standard output
 -s                Use standard in for input
 -h                Print help info
File control:
 -x                Delete original file after encryption/decryption

NOTE: Currently, RSA encryption does not work, so using any command line flags pertaining to RSA decryption/encryption or RSA key generation may result in unknown behavior. AES encryption, the focus of ucrypt, is fully functional however for testing.
