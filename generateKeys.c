#include <stdio.h>
#include <math.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEYSIZE 2048

int
main (int argc, char **argv)
{
  int ret = 0, bufsize = KEYSIZE / (sizeof (unsigned int) * 8);
  RSA *rsa;
  BIGNUM *bne = NULL;
  BIO *bp_private = NULL;
  FILE *pFile;
  int bits = 2048, i;
  unsigned long e = RSA_F4;
  unsigned char random_aes_key[bufsize], *random_aes_key_encrypted;
// generate the first key with RSA
  printf("Generating the first key with RSA\n");
  bne = BN_new ();
  if (BN_set_word (bne, e) != 1)
    goto free_all;
    
  rsa = RSA_new ();
  RSA_generate_key_ex (rsa, bits, bne, NULL);

  // generate the second key randomyl
  printf("Generating the second key randomly\n");
  for (i = 0; i < bufsize; i++)
    random_aes_key[i] = rand () % ((int) pow (8, sizeof (unsigned char)) - 1);

  random_aes_key_encrypted = malloc (RSA_size (rsa));

  if (-1 ==
      RSA_private_encrypt (bufsize, random_aes_key, random_aes_key_encrypted, rsa,
			  RSA_PKCS1_PADDING))
    goto free_all;

  
// write the public version of the first key on the disk
  printf("Writing the keys on the disk\n");
  bp_private = BIO_new_file ("firstKey.pem", "w+");
  if (PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL) != 1)
    {
      goto free_all;
    }

  // write on the disk the aes key encrypted with the first one
  pFile = fopen("secondKey.encrypted", "w+");
  fputs(random_aes_key_encrypted, pFile);
  fclose(pFile);
  
// free everything
free_all:

  BIO_free_all (bp_private);
  RSA_free (rsa);
  BN_free (bne);
 return (ret == 1);
}
