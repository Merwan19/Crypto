#ifndef PROC
#define PROC

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

#define K_LENGHT 256



void decrypt(FILE *ifp, FILE *ofp,char* ckey);
void encrypt(FILE *ifp, FILE *ofp,char* ckey);
int simpleSHA256(void* input, unsigned long length, unsigned char* md);

#endif
