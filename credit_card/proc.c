#include "proc.h"

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);
char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);

char K[K_LENGHT];

int
min (int a, int b)
{
  return a > b ? b : a;
}


int
main (int argc, char *argv[])
{


//<<------------- initialisation des variables ------------------->> //
  AES_KEY wctx;
  unsigned char c1[K_LENGHT];
  unsigned char c2[K_LENGHT];
  unsigned char K[K_LENGHT];
  unsigned char ligne[128];
  unsigned char str1[30];
  unsigned char strmode[10];
  FILE *fichier1 = NULL;
  FILE *fichier2 = NULL;
  FILE *fIN;
  FILE *fOUT;
  unsigned char dgst_c1[K_LENGHT];
  unsigned char dgst_c2[K_LENGHT];

//<<------------- Recuperation des clé en parametres ------------------->> //

  fichier1 = fopen (argv[1], "r+");
  if (fichier1 != NULL)
    {
      while (fgets (ligne, 128, fichier1) != NULL)
	{
	  strcat (c1, ligne);
	}
      //printf ("%s", c1);

      fclose (fichier1);
    }
  else
    {
      // On affiche un message d'erreur si on veut
      printf ("Impossible d'ouvrir le fichier %s", argv[1]);
      exit (EXIT_FAILURE);
    }


  fichier2 = fopen (argv[2], "r+");
  if (fichier2 != NULL)
    {
      // On peut lire et écrire dans le fichier
      while (fgets (ligne, 128, fichier2) != NULL)
	{
	  strcat (c2, ligne);
	}
      //printf ("%s", c2);

      fclose (fichier2);
    }
  else
    {
      // On affiche un message d'erreur si on veut
      printf ("Impossible d'ouvrir le fichier %s", argv[2]);
      exit (EXIT_FAILURE);
    }

//<<------------- Hash des clés c1 et c2 ------------------->> //

  if (simpleSHA256 (c1, 32, dgst_c1) == 1)
    {
      //  printf ("HashCrypted : \n%s\n", dgst_c1);
      //  printf ("Hash64 : %s\n", base64encode (dgst_c1, 32));
    }
  if (simpleSHA256 (c2, 32, dgst_c2) == 1)
    {
      // printf ("HashCrypted : \n%s\n", dgst_c2);
      //  printf ("Hash64 : %s\n", base64encode (dgst_c2, 32));
    }

//<<------------- Generation de la clé K et effacer les sous clé en mémoire----------------->> //
  AES_set_encrypt_key (c1, 128, &wctx);
  AES_encrypt (c2, K, &wctx);
  //printf ("final key K = %s\n", base64encode (K, 16));
  //printf ("final key K crypted = %s\n", K);
  memset (c1, 0, K_LENGHT);
  memset (c2, 0, K_LENGHT);


//<<------------- RAZ Crypter un fichier temoin ------------------->> //
/*
  fIN = fopen ("file.txt", "rb+");
  fOUT = fopen ("file.bin", "wb+");
  encrypt (fIN, fOUT, K);
  fclose (fIN);
  fclose (fOUT);
*/
//<<------------- Recherche dans le fichier ------------------->> //
//<<------------- Ecriture dans le fichier ------------------->> //
/*
  fIN = fopen ("file.bin", "rb+");
//  fOUT = fopen ("dec_file.txt", "wb+");
  decrypt_all (fIN, K);
  fclose (fIN);
*/

//  fclose (fOUT);
/*
fIN = fopen ("file2.bin", "rb+");
//  fOUT = fopen ("dec_file.txt", "wb+");
  decrypt_all (fIN, K);
  fclose (fIN);
*/

//<<------------- Boucle d'execution ------------------->> //
  while (1)
    {
      printf ("Select function : find , write , all, reset :\n>");
      scanf ("%s", strmode);
      if (strstr (strmode, "all"))
	{
	  printf ("<--------------FINDALL MODE------------------>\n");
	  fIN = fopen ("file.bin", "rb+");
	  decrypt_all (fIN, K);
	  fclose (fIN);
	}
      else if (strstr (strmode, "find"))
	{
	  printf ("<--------------FIND MODE------------------>\n");
	  printf ("Select a name or a cardNum\n");
	  scanf ("%s", str1);
	  fIN = fopen ("file.bin", "rb");
	  decrypt_search (fIN, K, str1);
	  fclose (fIN);
	}
      else if (strstr (strmode, "write"))
	{
	  printf ("<--------------WRITE MODE------------------>\n");
	  printf ("Enter a name and a cardNum format: \"id#cardnum\"\n");
	  scanf ("%s", str1);
	  if (NULL != strchr (str1, '#'))
	    {
	      fIN = fopen ("file.bin", "rb");
	      fOUT = fopen ("file2.bin", "wb+");
	      decrypt_write (fIN, fOUT, K, str1);
	    }
	  else
	    {
	      printf ("Line format not recognized\n");
	    }
	}
      else if (strstr (strmode, "reset"))
	{
	  fIN = fopen ("file.txt", "rb+");
	  fOUT = fopen ("file.bin", "wb+");
	  encrypt (fIN, fOUT, K);
	  fclose (fIN);
	  fclose (fOUT);
	}
      else
	{
	  printf ("<Wrong argument>\n");

	}




    }

  return 0;


}


char *
decrypt_write (FILE * ifp, FILE * fout, char *ckey, char *n)
{

  //Get file size
  fseek (ifp, 0L, SEEK_END);
  int fsize = ftell (ifp);
  //set back to normal
  fseek (ifp, 0L, SEEK_SET);

  int outLen1 = 0;
  int outLen2 = 0;
  unsigned char *indata = malloc (fsize);
  unsigned char *outdata = malloc (fsize + strlen (n) + 1);
  int i = 0;
  int j = 0;

  //Read File
  fread (indata, sizeof (char), fsize, ifp);

  //setup decryption
  EVP_CIPHER_CTX ctx;
  EVP_DecryptInit (&ctx, EVP_aes_128_ecb (), ckey, NULL);
  EVP_DecryptUpdate (&ctx, outdata, &outLen1, indata, fsize);
  EVP_DecryptFinal (&ctx, outdata + outLen1, &outLen2);


  fclose (ifp);
  FILE *ofp = fopen ("file.bin", "wb+");

//ecrit la ligne de saisie a la fin du buffer
  strcat (n, "\n");


  unsigned char *cherch = strchr (outdata, '\n');

  while (cherch != NULL)
    {
      i = strlen (outdata) - strlen (cherch) + 1;
      cherch = strchr (cherch + 1, '\n');

    }

  for (j = 0; j < strlen (n); j++)
    {
      outdata[i + j] = n[j];
    }
  outdata[i + j] = '\0';
  int fsize2 = strlen (outdata);

  outLen1 = 0;
  outLen2 = 0;
  unsigned char *out = malloc (fsize * 2);


  //Set up encryption
  EVP_CIPHER_CTX ctx_en;
  EVP_EncryptInit (&ctx_en, EVP_aes_128_ecb (), ckey, NULL);
  EVP_EncryptUpdate (&ctx_en, out, &outLen1, outdata, fsize2);
  EVP_EncryptFinal (&ctx_en, out + outLen1, &outLen2);
  fwrite (out, sizeof (char), outLen1 + outLen2, ofp);
  fclose (ofp);
}

void
decrypt_search (FILE * ifp, char *ckey, char *n)
{
  //Get file size
  fseek (ifp, 0L, SEEK_END);
  int fsize = ftell (ifp);
  //set back to normal
  fseek (ifp, 0L, SEEK_SET);

  int outLen1 = 0;
  int outLen2 = 0;
  unsigned char *indata = malloc (fsize);
  unsigned char *outdata = malloc (fsize * 2);
  int i = 0;
  int j = 0;
  int u = 0;
  int k = 0;
  unsigned char *ligne;

  int ns = 0;
  while (n[ns] != '\0')
    ns++;

  unsigned char *ncpy = malloc (ns * sizeof (char));
  memcpy (ncpy, n, ns);
  //Read File
  fread (indata, sizeof (char), fsize, ifp);

  //setup decryption
  EVP_CIPHER_CTX ctx;
  EVP_DecryptInit (&ctx, EVP_aes_128_ecb (), ckey, NULL);
  EVP_DecryptUpdate (&ctx, outdata, &outLen1, indata, fsize);
  EVP_DecryptFinal (&ctx, outdata + outLen1, &outLen2);
  outdata[outLen1 + outLen2] = '\0';


  while (outdata[k] != '\0')
    {
      u = 0;
      while (outdata[k + u] != '\n' && outdata[k + u] != '\0')
	u++;
      ligne = malloc (u * sizeof (char));
      memcpy (ligne, outdata + k * sizeof (char), u);
      ligne[u] = '\0';
      i = ns < u && ligne[ns] == '#';
      for (j = 0; j < ns && j < u; j++)
	{
	  i = i && (ligne[j] == ncpy[j]);
	}
      if (i == 1 && u > 1)
	{
	  printf ("===>%s\n", ligne);
	}
      free (ligne);
      k += u + 1;
    }

}

void
decrypt_all (FILE * ifp, char *ckey)
{

  //Get file size
  fseek (ifp, 0L, SEEK_END);
  int fsize = ftell (ifp);
  //set back to normal
  fseek (ifp, 0L, SEEK_SET);

  int outLen1 = 0;
  int outLen2 = 0;
  unsigned char *indata = malloc (fsize);
  unsigned char *outdata = malloc (fsize);
  int i = 0;
  int j = 0;

  //Read File
  fread (indata, sizeof (char), fsize, ifp);

  //setup decryption
  EVP_CIPHER_CTX ctx;
  EVP_DecryptInit (&ctx, EVP_aes_128_ecb (), ckey, NULL);
  EVP_DecryptUpdate (&ctx, outdata, &outLen1, indata, fsize);
  EVP_DecryptFinal (&ctx, outdata + outLen1, &outLen2);
  outdata[outLen1 + outLen2] = '\0';
  printf ("%s", outdata);


}



void
decrypt (FILE * ifp, FILE * ofp, char *ckey)
{

  int i = 0;
  //Get file size
  fseek (ifp, 0L, SEEK_END);
  int fsize = ftell (ifp);
  //set back to normal
  fseek (ifp, 0L, SEEK_SET);

  int outLen1 = 0;
  int outLen2 = 0;
  unsigned char *indata = malloc (fsize);
  unsigned char *outdata = malloc (fsize);

  //Read File
  fread (indata, sizeof (char), fsize, ifp);

  //setup decryption
  EVP_CIPHER_CTX ctx;
  EVP_DecryptInit (&ctx, EVP_aes_128_ecb (), ckey, NULL);
  EVP_DecryptUpdate (&ctx, outdata, &outLen1, indata, fsize);
  EVP_DecryptFinal (&ctx, outdata + outLen1, &outLen2);


  unsigned char *cherch = strchr (outdata, '\n');
  while (cherch != NULL)
    {
      while (i < strlen (outdata) - strlen (cherch) + 1)
	{
	  printf ("%c", outdata[i]);
	  i++;
	}
      i = strlen (outdata) - strlen (cherch) + 1;
      cherch = strchr (cherch + 1, '\n');
    }
  fwrite (outdata, sizeof (char), outLen1 + outLen2, ofp);
}




void
encrypt (FILE * ifp, FILE * ofp, char *ckey)
{
  //Get file size
  fseek (ifp, 0L, SEEK_END);
  int fsize = ftell (ifp);
  //set back to normal
  fseek (ifp, 0L, SEEK_SET);

  int outLen1 = 0;
  int outLen2 = 0;
  unsigned char *indata = malloc (fsize);
  unsigned char *outdata = malloc (fsize * 2);

  //Read File
  fread (indata, sizeof (char), fsize, ifp);

  //Set up encryption
  EVP_CIPHER_CTX ctx;
  EVP_EncryptInit (&ctx, EVP_aes_128_ecb (), ckey, NULL);
  EVP_EncryptUpdate (&ctx, outdata, &outLen1, indata, fsize);
  EVP_EncryptFinal (&ctx, outdata + outLen1, &outLen2);
  fwrite (outdata, sizeof (char), outLen1 + outLen2, ofp);
}



int
simpleSHA256 (void *input, unsigned long length, unsigned char *md)
{
  int i;
  for (i = 0; i < length; i++)
    md[i] = '\0';

  SHA256_CTX context;
  if (!SHA256_Init (&context))
    return 0;

  if (!SHA256_Update (&context, (unsigned char *) input, length))
    return 0;

  if (!SHA256_Final (md, &context))
    return 0;

  return 1;
}

char *
base64encode (const void *b64_encode_this, int encode_this_many_bytes)
{
  BIO *b64_bio, *mem_bio;	//Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
  BUF_MEM *mem_bio_mem_ptr;	//Pointer to a "memory BIO" structure holding our base64 data.
  b64_bio = BIO_new (BIO_f_base64 ());	//Initialize our base64 filter BIO.
  mem_bio = BIO_new (BIO_s_mem ());	//Initialize our memory sink BIO.
  BIO_push (b64_bio, mem_bio);	//Link the BIOs by creating a filter-sink BIO chain.
  BIO_set_flags (b64_bio, BIO_FLAGS_BASE64_NO_NL);	//No newlines every 64 characters or less.
  BIO_write (b64_bio, b64_encode_this, encode_this_many_bytes);	//Records base64 encoded data.
  BIO_flush (b64_bio);		//Flush data.  Necessary for b64 encoding, because of pad characters.
  BIO_get_mem_ptr (mem_bio, &mem_bio_mem_ptr);	//Store address of mem_bio's memory structure.
  BIO_set_close (mem_bio, BIO_NOCLOSE);	//Permit access to mem_ptr after BIOs are destroyed.
  BIO_free_all (b64_bio);	//Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
  BUF_MEM_grow (mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);	//Makes space for end null.
  (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';	//Adds null-terminator to tail.
  return (*mem_bio_mem_ptr).data;	//Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

char *
base64decode (const void *b64_decode_this, int decode_this_many_bytes)
{
  BIO *b64_bio, *mem_bio;	//Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
  char *base64_decoded = calloc ((decode_this_many_bytes * 3) / 4 + 1, sizeof (char));	//+1 = null.
  b64_bio = BIO_new (BIO_f_base64 ());	//Initialize our base64 filter BIO.
  mem_bio = BIO_new (BIO_s_mem ());	//Initialize our memory source BIO.
  BIO_write (mem_bio, b64_decode_this, decode_this_many_bytes);	//Base64 data saved in source.
  BIO_push (b64_bio, mem_bio);	//Link the BIOs by creating a filter-source BIO chain.
  BIO_set_flags (b64_bio, BIO_FLAGS_BASE64_NO_NL);	//Don't require trailing newlines.
  int decoded_byte_index = 0;	//Index where the next base64_decoded byte should be written.
  while (0 < BIO_read (b64_bio, base64_decoded + decoded_byte_index, 1))
    {				//Read byte-by-byte.
      decoded_byte_index++;	//Increment the index until read of BIO decoded data is complete.
    }				//Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
  BIO_free_all (b64_bio);	//Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
  return base64_decoded;	//Returns base-64 decoded data with trailing null terminator.
}
