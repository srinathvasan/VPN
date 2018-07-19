//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"

BIO *bio_err = 0;
char* pass;
int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}
int passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
    if (size<strlen(pass)+1)
    	return (0);
    strcpy(buf,pass);
    return(strlen(pass));
}
//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	/* In this function, you handle
	 * 1) The SSL handshake between the server and the client.
	 * 2) Authentication
	 * 		a) Both the server and the client rejects if the presented certificate is not signed by the trusted CA.
	 * 		b) Client rejects if the the server's certificate does not contain a pre-defined string of your choice in the common name (CN) in the subject.
	 */

	SSL_library_init();
		SSL_load_error_strings();
		SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
		BIO* bio;
		SSL *ssl;

		 if ( ctx == NULL )
		    {
		        ERR_print_errors_fp(stderr);
		        abort();
		    }
		 //SSL_CTX_use_certificate_file(ctx,certfile, SSL_FILETYPE_PEM);
		 if ( SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0 )
		        {
			 printf("1");
		            ERR_print_errors_fp(stderr);
		            abort();
		        }
		 pass="vamshi";
		 	SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
		 if ( SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) <= 0 )
		        {
			 printf("2");
		            ERR_print_errors_fp(stderr);
		            abort();
		        }
		    if ( !SSL_CTX_check_private_key(ctx) )
		        {
		            fprintf(stderr, "Private key does not match the public certificate\n");
		            abort();
		        }
		    if(SSL_CTX_load_verify_locations(ctx, rootCApath, NULL) )
		    {
		    ERR_print_errors_fp(stderr);

		    }
		    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		//  SSL_CTX_set_verify_depth(ctx,1);

		    ssl = SSL_new(ctx);
		    bio = BIO_new_socket(contChannel, BIO_NOCLOSE);
		    SSL_set_bio(ssl, bio, bio);
		    SSL_connect(ssl);
		    const char *commonName = "TP Server vamshi@kth.se srinathv@kth.se";
		        X509 *peer;
		        char peer_CN[256];
		        peer = SSL_get_peer_certificate(ssl);
		        X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName,peer_CN,256);
		        if(strcasecmp(peer_CN,commonName))
		        berr_exit("Common name doesn't match host name");


	return ssl;

}

unsigned char *key = new unsigned char[32];

unsigned char *iv = new unsigned char[16];

void dataChannelKeyExchange(int role, SSL *ssl) {
	/* In this function, you handle
	 * 1) The generation of the key and the IV that is needed to symmetrically encrypt/decrypt the IP datagrams over UDP (data channel).
	 * 2) The exchange of the symmetric key and the IV over the control channel secured by the SSL object.
	 */

	SSL_read(ssl, key, 32);
	SSL_read(ssl, iv, 16);



}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plainText, int plainTextLen,
		unsigned char *cipherText) {
	/* In this function, you store the symmetrically encrypted form of the IP datagram at *plainText, into the memory at *cipherText.
	 * The memcpy below directly copies *plainText into *cipherText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */
	//memcpy(cipherText, plainText, plainTextLen);

	//return plainTextLen;

	EVP_CIPHER_CTX *ctx;

	  int len;

	  int ciphertext_len;

	  /* Create and initialise the context */
	  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
	   * and IV size appropriate for your cipher
	   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	   * IV size for *most* modes is the same as the block size. For AES this
	   * is 128 bits */
	  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	    handleErrors();

	  /* Provide the message to be encrypted, and obtain the encrypted output.
	   * EVP_EncryptUpdate can be called multiple times if necessary
	   */
	  if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
	    handleErrors();
	  ciphertext_len = len;

	  /* Finalise the encryption. Further ciphertext bytes may be written at
	   * this stage.
	   */
	  if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) handleErrors();
	  ciphertext_len += len;

	  /* Clean up */
	  EVP_CIPHER_CTX_free(ctx);

	  return ciphertext_len;

}

int decrypt(unsigned char *cipherText, int cipherTextLen,
		unsigned char *plainText) {
	/* In this function, you symmetrically decrypt the data at *cipherText and store the output IP datagram at *plainText.
	 * The memcpy below directly copies *cipherText into *plainText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */
	//memcpy(plainText, cipherText, cipherTextLen);

	//return cipherTextLen;

	if(cipherTextLen % 16 !=0){
		 return 0;
	 }

	 EVP_CIPHER_CTX *ctx;

	  int len;

	  int plaintext_len;

	  /* Create and initialise the context */
	  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
	   * and IV size appropriate for your cipher
	   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	   * IV size for *most* modes is the same as the block size. For AES this
	   * is 128 bits */
	  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	    handleErrors();

	  /* Provide the message to be decrypted, and obtain the plaintext output.
	   * EVP_DecryptUpdate can be called multiple times if necessary
	   */
	  if(1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
	    handleErrors();
	  plaintext_len = len;

	  /* Finalise the decryption. Further plaintext bytes may be written at
	   * this stage.
	   */
	  if(1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
	  plaintext_len += len;

	  /* Clean up */
	  EVP_CIPHER_CTX_free(ctx);

	  return plaintext_len;

}
