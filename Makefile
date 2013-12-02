  # compiler:
  CC = g++

  # compiler flags:
  CXXFLAGS  = -g -Wall -std=c++0x

  # build target executable:
  TARGET = ucrypt

  # object file targets:
  OBJS = B64coder.o AEScrypt.o RSAcrypt.o ucrypt.o

  # required directories:
  ENCDIR = Encrypted
  DECDIR = Decrypted
  RSADIR = RSA

  # required libraries:
  LIBS = -lgmp -lhl++

  # build rules:
  ucrypt: $(OBJS)
	@$(CC) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS)
	@rm -f *.o
	@mkdir -p $(DECDIR)
	@mkdir -p $(ENCDIR)
	@mkdir -p $(RSADIR)  

  ucrypt.o: ucrypt.cpp AEScrypt.h RSAcrypt.h
	@$(CC) $(CXXFLAGS) -c ucrypt.cpp

  AEScrypt.o: AEScrypt.cpp AEScrypt.h
	@$(CC) $(CXXFLAGS) -c AEScrypt.cpp

  RSAcrypt.o: RSAcrypt.cpp RSAcrypt.h
	@$(CC) $(CXXFLAGS) -c RSAcrypt.cpp

  B64coder.o: B64coder.cpp B64coder.h
	@$(CC) $(CXXFLAGS) -c B64coder.cpp
