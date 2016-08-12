/** 
 *   HTTP Chat server with authentication and multi-channeling.
 *
 *   Copyright (C) 2016  Maxim Alov
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#if SECURE

#include <gtest/gtest.h>
#include <string>
#include <cstdio>
#include "common.h"
#include "crypting/includes.h"
#include "crypting/random_util.h"
#include "logger.h"

namespace test {

// @see https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope

/* Fixture */
// ----------------------------------------------------------------------------
class EVPfixture : public ::testing::Test {
protected:
  EVPfixture() { --s_id; }
  void SetUp() override;
  void TearDown() override;

protected:
  static ID_t s_id;
  std::pair<secure::Key, secure::Key> m_key_pair;
};

ID_t EVPfixture::s_id = 800;

void EVPfixture::SetUp() {
  bool accessible = false;
  const size_t size = 80;
  std::string input = secure::random::generateString(size);
  secure::random::generateKeyPair(s_id, input.c_str(), size);
  m_key_pair = secure::random::loadKeyPair(s_id, &accessible);
}

void EVPfixture::TearDown() {
  auto public_key_filename  = common::createFilenameWithId(s_id, PUBLIC_KEY_FILE);
  auto private_key_filename = common::createFilenameWithId(s_id, PRIVATE_KEY_FILE);
  if (remove(public_key_filename.c_str()) != 0) {
    ERR("Failed to delete file: %s", public_key_filename.c_str());
  }
  if (remove(private_key_filename.c_str()) != 0) {
    ERR("Failed to delete file: %s", private_key_filename.c_str());
  }
}

/* Core utils */
// ----------------------------------------------
void handleErrors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int envelopeSeal(
    EVP_PKEY** pub_key,
    unsigned char* plaintext, int plaintext_len,
    unsigned char** encrypted_key, int* encrypted_key_len,
    unsigned char* iv,
    unsigned char* ciphertext) {

  EVP_CIPHER_CTX* ctx;
  int ciphertext_len = 0;
  int len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
  }

  /* Initialise the envelope seal operation. This operation generates
   * a key for the provided cipher, and then encrypts that key a number
   * of times (one for each public key provided in the pub_key array). In
   * this example the array size is just one. This operation also
   * generates an IV and places it in iv. */
  if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, 1)) {
    handleErrors();
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_SealUpdate can be called multiple times if necessary
   */
  if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    handleErrors();
  }

  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) {
    handleErrors();
  }

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int envelopeOpen(
    EVP_PKEY* priv_key,
    unsigned char* ciphertext, int ciphertext_len,
    unsigned char* encrypted_key, int encrypted_key_len,
    unsigned char* iv,
    unsigned char* plaintext) {

  EVP_CIPHER_CTX* ctx;
  int len = 0;
  int plaintext_len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
  }

  /* Initialise the decryption operation. The asymmetric private key is
   * provided and priv_key, whilst the encrypted session key is held in
   * encrypted_key */
  if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, priv_key)) {
    handleErrors();
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_OpenUpdate can be called multiple times if necessary
   */
  if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    handleErrors();
  }

  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) {
    handleErrors();
  }

  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/* Tests */
// ----------------------------------------------------------------------------
TEST_F(EVPfixture, RSAFileKeys) {
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";
  int msg256_len = strlen(msg256);

  /* encrypt */
  // --------------------------------------------
  FILE* public_file = fopen("../test/crypting/public.pem", "rt");
  RSA* public_rsa = RSA_new();
  EVP_PKEY* public_key = EVP_PKEY_new();
  PEM_read_RSAPublicKey(public_file, &public_rsa, nullptr, nullptr);
  EVP_PKEY_assign_RSA(public_key, public_rsa);
  fclose(public_file);

  int pubkey_len = EVP_PKEY_size(public_key);
  int ek_len = 0, iv_len = 0, cipher_len = 0;
  unsigned char* ek = new unsigned char[pubkey_len];
  unsigned char* iv = new unsigned char[EVP_MAX_IV_LENGTH];
  unsigned char* cipher = new unsigned char[msg256_len + EVP_MAX_IV_LENGTH];

  cipher_len = envelopeSeal(&public_key, (unsigned char*) msg256, msg256_len, &ek, &ek_len, iv, cipher);
  EVP_PKEY_free(public_key);

  /* decrypt */
  // --------------------------------------------
  FILE* private_file = fopen("../test/crypting/private.pem", "rt");
  RSA* private_rsa = RSA_new();
  EVP_PKEY* private_key = EVP_PKEY_new();
  PEM_read_RSAPrivateKey(private_file, &private_rsa, nullptr, nullptr);
  EVP_PKEY_assign_RSA(private_key, private_rsa);
  fclose(private_file);

  unsigned char* plain = new unsigned char[cipher_len + iv_len];
  int plain_len = envelopeOpen(private_key, cipher, cipher_len, ek, ek_len, iv, plain);
  plain[plain_len] = '\0';
  EVP_PKEY_free(private_key);

  /* check */
  // --------------------------------------------
  EXPECT_STREQ(msg256, (const char*) plain);

  /* clean up */
  // --------------------------------------------
  delete [] ek;  ek = nullptr;
  delete [] iv;  iv = nullptr;
  delete [] cipher;  cipher = nullptr;
  delete [] plain;   plain = nullptr;
}

// ----------------------------------------------
TEST_F(EVPfixture, RSARawKeys) {
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";
  int msg256_len = strlen(msg256);

  std::string public_pem = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAtaucDkZfJF65TPZ4p6PiFpG2EK+zOxG5O4KIj7WjlO5/KS5jEf+6\noqpjsb0dhlTh7BjDC9Eslb1TGuaUMA4pwX1GYYHShcpqasIXYMZM0rUryZqSB5Xe\nrh4JdTpZcIvqnwF+hNqIx0W4SkyR8C99IMOJ3TXbZdUaAP56Uqa8jNiND3/inJZD\nqEZMpZ88eu9Tb+7xWxkcLjRSOdQrmGscj0c0qQF3POXkzcy08OHYzozY12fhe40E\nOAqvyWWDQt6mZlwfXp9OQRuU+r4L9jHlNkosIYVdLKY6f+yP2kx7tJVYQ5ISSA70\no1vlO6kKXhnLMAar8ad5F5O1ZQRdJeMwPQIDAQAB\n-----END RSA PUBLIC KEY-----";

  std::string private_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtaucDkZfJF65TPZ4p6PiFpG2EK+zOxG5O4KIj7WjlO5/KS5j\nEf+6oqpjsb0dhlTh7BjDC9Eslb1TGuaUMA4pwX1GYYHShcpqasIXYMZM0rUryZqS\nB5Xerh4JdTpZcIvqnwF+hNqIx0W4SkyR8C99IMOJ3TXbZdUaAP56Uqa8jNiND3/i\nnJZDqEZMpZ88eu9Tb+7xWxkcLjRSOdQrmGscj0c0qQF3POXkzcy08OHYzozY12fh\ne40EOAqvyWWDQt6mZlwfXp9OQRuU+r4L9jHlNkosIYVdLKY6f+yP2kx7tJVYQ5IS\nSA70o1vlO6kKXhnLMAar8ad5F5O1ZQRdJeMwPQIDAQABAoIBAQCj1+vcq/butEdm\nc/uJJbKoLC4JioyYv3lRhH5pLaYkkZw5pc5P01WdkxJqoGbaWf+PkR2HsNUHD0K+\nRipr1Lov+S3ajt0xMMcdFYNEElQCzMZ7Al6lXLMCUbCx+zfi2y10zkIuy3EEV4rH\n55rPBeVSAUh7KzF9+92B/ACSPjJaywUgIykgBDLaW8acrJenGUt/s/KwDlSDfT79\nijq2I/D2KaF4K1DYwkZ2FB0Awyb5S5R7Ku+9YBbjyj0tDQ5kiJYLsCAIWos1KTS7\ndfp3U88r+Scqy8MHN4RRr6qkFIQgvQO60K6THfqtGciNP/FzGsrR2ciSf3lOTMYc\ngnktFBmBAoGBAOej/iLDj3r+F8QoRpMbUNy3juMPIlXV9Sw6KPe4CG4nqevv5wJl\ns/5B9ffhStooSR5u4LfXYNQ9aT2XXefk1zYmQftc/Lxph2BborBkl7WwpsK3QXp+\nWdK22z7NIECMnn5tEVVFGPdass44fcRDDpmtm9L3Jblx/SV+pFL4EFPtAoGBAMjG\nXZQSUFvI3HzCQCMOPYL0s9znWIKdOfdbX1GjkFysrVq7qfzvb6ZJeUIB9pOqtvKf\nwxFincSH9ibK0yiQ9bIDoQ8MyirdX04CFJWBg9fXlVAn31vqZVZ7PGtXy1vILdrr\n43mcOyaiKsjvBKUpjV0Yivl++NuF/voYbIp9C2ORAoGAI5I7ZHtDfU+ntqe4rr5z\nHHHTr2qTizrf+3qy79eC8+eDYIfmoaecjF70tqwSIo4tLE86kwCwDeegUaT89q9d\nnSMi3sbYyNYrw9BOm2fXJD+MXDpoA7eDc6hA4tP9L+xoKmH1V3LU8qcq7iAesBTc\nGR1f4HWzhVbL2QYpldQiLcECgYAOtHimH7FDB7MecBvCdYiLzuBdjZQt/NYCB+8z\nS4eHQh5wRs5seBz1UOxQqVQl/JrpqknfPBnSCyM8NB7DGdrk7t8c+xLTkOMqE3zu\ndk3xwRhuhn0VflVtwBjsw8FhN4gkQKKohYjPi5EWpmrwrdpstx92ppYTffzu1Fse\nyYnMAQKBgCynG+Otqwiowe8DfgrOyPV7cOG59FK49j6pZACqBzXm0q3dbBID+OZA\nGr1pv0nnMrY4ITM75jYMlL7gSCyJzGwvD251o1nHfBhuDe20mBp9u5DHYe95ENaV\nQCP05gaTTfYQobvfUZo2ikMEap3bX1ZXMH1rNigIGlf+0PYk/qH0\n-----END RSA PRIVATE KEY-----";

  /* encrypt */
  // --------------------------------------------
  BIO* public_bio = BIO_new(BIO_s_mem());
  BIO_write(public_bio, public_pem.c_str(), public_pem.length());
  RSA* public_rsa = RSA_new();
  EVP_PKEY* public_key = EVP_PKEY_new();
  PEM_read_bio_RSAPublicKey(public_bio, &public_rsa, nullptr, nullptr);
  EVP_PKEY_assign_RSA(public_key, public_rsa);
  BIO_free(public_bio);

  int pubkey_len = EVP_PKEY_size(public_key);
  int ek_len = 0, iv_len = 0, cipher_len = 0;
  unsigned char* ek = new unsigned char[pubkey_len];
  unsigned char* iv = new unsigned char[EVP_MAX_IV_LENGTH];
  unsigned char* cipher = new unsigned char[msg256_len + EVP_MAX_IV_LENGTH];

  cipher_len = envelopeSeal(&public_key, (unsigned char*) msg256, msg256_len, &ek, &ek_len, iv, cipher);
  EVP_PKEY_free(public_key);

  /* decrypt */
  // --------------------------------------------
  BIO* private_bio = BIO_new(BIO_s_mem());
  BIO_write(private_bio, private_pem.c_str(), private_pem.length());
  RSA* private_rsa = RSA_new();
  EVP_PKEY* private_key = EVP_PKEY_new();
  PEM_read_bio_RSAPrivateKey(private_bio, &private_rsa, nullptr, nullptr);
  EVP_PKEY_assign_RSA(private_key, private_rsa);
  BIO_free(private_bio);

  unsigned char* plain = new unsigned char[cipher_len + iv_len];
  int plain_len = envelopeOpen(private_key, cipher, cipher_len, ek, ek_len, iv, plain);
  plain[plain_len] = '\0';
  EVP_PKEY_free(private_key);

  /* check */
  // --------------------------------------------
  EXPECT_STREQ(msg256, (const char*) plain);

  /* clean up */
  // --------------------------------------------
  delete [] ek;  ek = nullptr;
  delete [] iv;  iv = nullptr;
  delete [] cipher;  cipher = nullptr;
  delete [] plain;   plain = nullptr;
}

// ----------------------------------------------
TEST_F(EVPfixture, Separate) {

}

}

#endif  // SECURE

