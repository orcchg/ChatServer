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
#include "crypting/aes_cryptor.h"
#include "crypting/random_util.h"
#include "crypting/rsa_cryptor.h"
#include "logger.h"

namespace test {

/* Fixture */
// ----------------------------------------------------------------------------
class RSACryptorTest : public ::testing::Test {
protected:
  RSACryptorTest() { --s_id; }
  void SetUp() override;
  void TearDown() override;

protected:
  static ID_t s_id;
  std::pair<secure::Key, secure::Key> m_key_pair;
};

ID_t RSACryptorTest::s_id = 900;

void RSACryptorTest::SetUp() {
  bool accessible = false;
  const size_t size = 80;
  std::string input = secure::random::generateString(size);
  secure::random::generateKeyPair(s_id, input.c_str(), size);
  m_key_pair = secure::random::loadKeyPair(s_id, &accessible);
}

void RSACryptorTest::TearDown() {
  auto public_key_filename  = common::createFilenameWithId(s_id, PUBLIC_KEY_FILE);
  auto private_key_filename = common::createFilenameWithId(s_id, PRIVATE_KEY_FILE);
  if (remove(public_key_filename.c_str()) != 0) {
    ERR("Failed to delete file: %s", public_key_filename.c_str());
  }
  if (remove(private_key_filename.c_str()) != 0) {
    ERR("Failed to delete file: %s", private_key_filename.c_str());
  }
}

/* Tests */
// ----------------------------------------------------------------------------
// @see https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
static bool Encrypt(RSA* keypair, const char* msg256, char** encrypt, int& encrypt_len) {
  encrypt_len = RSA_public_encrypt(strlen(msg256) + 1, (unsigned char*) msg256, (unsigned char*) *encrypt, keypair, RSA_PKCS1_OAEP_PADDING);
  if (encrypt_len == -1 || encrypt_len != 256) {
    char* error = (char*) malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), error);
    ERR("Error encrypting message: %s\n", error);
    free(error);
    return false;
  }
  return true;
}

static bool Decrypt(RSA* keypair, char* encrypt, int encrypt_len, char** decrypt, int& decrypt_len) {
  decrypt_len = RSA_private_decrypt(encrypt_len, (unsigned char*) encrypt, (unsigned char*) *decrypt, keypair, RSA_PKCS1_OAEP_PADDING);
  if (decrypt_len == -1) {
    char* error = (char*) malloc(130);
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), error);
    ERR("Error decrypting message: %s\n", error);
    free(error);
    return false;
  }
  return true;
}

static void readKeysFromPEM(const char* pubfiles, const char* prifiles, RSA** rsa) {
  FILE* pubfile = fopen(pubfiles, "rt");
  FILE* prifile = fopen(prifiles, "rt");
  PEM_read_RSAPublicKey(pubfile, rsa, nullptr, nullptr);
  PEM_read_RSAPrivateKey(prifile, rsa, nullptr, nullptr);
  fclose(pubfile);
  fclose(prifile);
}

static int EncryptEVP(
    const char* msg256,
    int msg256_len,
    EVP_PKEY* keypair,
    unsigned char** ek,
    int* ek_len,
    unsigned char** iv,
    int* iv_len,
    unsigned char** cipher) {
  *iv_len = EVP_MAX_IV_LENGTH;
  int block_len = 0;
  int cipher_len = 0;

  EVP_CIPHER_CTX* rsa_enc_ctx = EVP_CIPHER_CTX_new();
  EVP_SealInit(rsa_enc_ctx, EVP_aes_256_cbc(), ek, ek_len, *iv, &keypair, 1);
  EVP_SealUpdate(rsa_enc_ctx, *cipher, &block_len, (unsigned char*) msg256, msg256_len);
  cipher_len += block_len;
  EVP_SealFinal(rsa_enc_ctx, *cipher + cipher_len, &block_len);
  cipher_len += block_len;
  EVP_CIPHER_CTX_free(rsa_enc_ctx);
  INF("RSA Cipher length: %i", cipher_len);
  TTY("RSA Cipher[%i]: %.*s", cipher_len, cipher_len, *cipher);
  return cipher_len;
}

static int DecryptEVP(
    unsigned char** plain,
    EVP_PKEY* keypair,
    unsigned char* ek,
    int ek_len,
    unsigned char* iv,
    int iv_len,
    unsigned char* cipher,
    int cipher_len) {
  int block_len = 0;
  int plain_len = 0;

  EVP_CIPHER_CTX* rsa_dec_ctx = EVP_CIPHER_CTX_new();
  EVP_OpenInit(rsa_dec_ctx, EVP_aes_256_cbc(), ek, ek_len, iv, keypair);
  EVP_OpenUpdate(rsa_dec_ctx, *plain, &block_len, cipher, cipher_len);
  plain_len += block_len;
  EVP_OpenFinal(rsa_dec_ctx, *plain + plain_len, &block_len);
  plain_len += block_len;
  EVP_CIPHER_CTX_free(rsa_dec_ctx);
  INF("RSA Plain length: %i", plain_len);
  TTY("RSA Plain[%i]: %.*s", plain_len, plain_len, *plain);
  (*plain)[plain_len] = '\0';
  return plain_len;
}

/* Tests */
// ----------------------------------------------------------------------------
TEST(RSACrypting, Direct) {
  // 255 chars + '\0', in practise must be not greater than (214 + '\0') due to padding
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna. Maecenas quis mi est blandit";

  // encrypt
  RSA* keypair = RSA_generate_key(2048, 65537 /* exponent */, nullptr, nullptr);
  char* encrypt = (char*) malloc(RSA_size(keypair));
  int encrypt_len = 0;
  EXPECT_TRUE(Encrypt(keypair, msg256, &encrypt, encrypt_len));

  // decrypt
  char* decrypt = (char*) malloc(RSA_size(keypair));
  int decrypt_len = 0;
  EXPECT_TRUE(Decrypt(keypair, encrypt, encrypt_len, &decrypt, decrypt_len));

  EXPECT_STREQ(msg256, decrypt);

  RSA_free(keypair);
  free(encrypt);
  free(decrypt); 
}

// @see http://stackoverflow.com/questions/12647220/reading-and-writing-rsa-keys-to-a-pem-file-in-c
TEST(RSACrypting, File) {
  // 255 chars + '\0', in practise must be not greater than (214 + '\0') due to padding
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna. Maecenas quis mi est blandit";

  // generate keys and store them into PEM files
  secure::random::generateKeyPair(900, "01234567890123456789", 20);

  // read keys from PEM files
  BIO* pri = BIO_new(BIO_s_mem());
  BIO* pub = BIO_new(BIO_s_mem());

  RSA* rsa = RSA_new();
  readKeysFromPEM("id_900_public.pem", "id_900_private.pem", &rsa);

  // encrypt
  char* encrypt = (char*) malloc(RSA_size(rsa));
  int encrypt_len = 0;
  EXPECT_TRUE(Encrypt(rsa, msg256, &encrypt, encrypt_len));
  TTY("encrypted message: %.*s", encrypt_len, encrypt);

  // decrypt
  char* decrypt = (char*) malloc(RSA_size(rsa));
  int decrypt_len = 0;
  EXPECT_TRUE(Decrypt(rsa, encrypt, encrypt_len, &decrypt, decrypt_len));
  TTY("decrypted message: %.*s", decrypt_len, decrypt);

  EXPECT_STREQ(msg256, decrypt);

  BIO_free_all(pub);
  BIO_free_all(pri);
  RSA_free(rsa);
  free(encrypt);
  free(decrypt);

  remove("id_900_private.pem");
  remove("id_900_public.pem");
}

TEST(RSACrypting, FileFixedKeys) {
  // 255 chars + '\0', in practise must be not greater than (214 + '\0') due to padding
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna. Maecenas quis mi est blandit";

  // read keys from PEM files
  BIO* pri = BIO_new(BIO_s_mem());
  BIO* pub = BIO_new(BIO_s_mem());

  RSA* rsa = RSA_new();
  readKeysFromPEM("../test/crypting/public.pem", "../test/crypting/private.pem", &rsa);

  // encrypt
  char* encrypt = (char*) malloc(RSA_size(rsa));
  int encrypt_len = 0;
  EXPECT_TRUE(Encrypt(rsa, msg256, &encrypt, encrypt_len));
  TTY("encrypted message: %.*s", encrypt_len, encrypt);

  // decrypt
  char* decrypt = (char*) malloc(RSA_size(rsa));
  int decrypt_len = 0;
  EXPECT_TRUE(Decrypt(rsa, encrypt, encrypt_len, &decrypt, decrypt_len));
  TTY("decrypted message: %.*s", decrypt_len, decrypt);

  EXPECT_STREQ(msg256, decrypt);

  BIO_free_all(pub);
  BIO_free_all(pri);
  RSA_free(rsa);
  free(encrypt);
  free(decrypt);
}

// @see https://shanetully.com/2012/06/openssl-rsa-aes-and-c/
TEST(RSACrypting, Envelope) {
  // message of any length is possible for EVP
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";
  int msg256_len = strlen(msg256);

  // ============================================
  /*
   * RSA: generate key pair
   */
  EVP_PKEY* keypair = nullptr;
  EVP_PKEY_CTX* rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(rsa_ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, RSA_KEYLEN);
  EVP_PKEY_keygen(rsa_ctx, &keypair);
  EVP_PKEY_CTX_free(rsa_ctx);

  PEM_write_PrivateKey(stdout, keypair, nullptr, nullptr, 0, 0, nullptr);
  PEM_write_PUBKEY(stdout, keypair);

  // ============================================
  /*
   * RSA: encrypt with public key
   */
  int pubkey_len = EVP_PKEY_size(keypair);
  int ek_len = 0, iv_len = 0;
  unsigned char* ek = new unsigned char[pubkey_len];
  unsigned char* iv = new unsigned char[EVP_MAX_IV_LENGTH];
  unsigned char* cipher = new unsigned char[msg256_len + EVP_MAX_IV_LENGTH];
  int cipher_len = EncryptEVP(msg256, msg256_len, keypair, &ek, &ek_len, &iv, &iv_len, &cipher);

  // ============================================
  /*
   * RSA: decrypt with private key
   */
  unsigned char* plain = new unsigned char[cipher_len + iv_len];
  int plain_len = DecryptEVP(&plain, keypair, ek, ek_len, iv, iv_len, cipher, cipher_len);
  EXPECT_STREQ(msg256, (const char*) plain);

  // ============================================
  /*
   * free
   */
  delete [] ek;  ek = nullptr;
  delete [] iv;  iv = nullptr;
  delete [] cipher;  cipher = nullptr;
  delete [] plain;  plain = nullptr;

  EVP_PKEY_free(keypair);
}

TEST(RSACrypting, EnvelopeMemory) {
  // message of any length is possible for EVP
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";
  int msg256_len = strlen(msg256);

  // ============================================
  /*
   * RSA: read key pair
   */
  std::string public_pem = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASav\njS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4\neP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7x\nyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOG\ni11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZ\nF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB\n-----END RSA PUBLIC KEY-----";

  std::string private_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAx92l9nphMp3WWHxmn8CVoN5Z8osCbkVwFKtSHq8Wo4QiP2zR\ns0lH5ghDhid/ZqZBXFPM8ZxIXUWloQzD1AnI6Q60jHLAT1tWForKtIdUdzY+H1TM\n967HIAQXQCW+tatrRD2ZzeqQDHhed0NkQj0/LCgVVzaHEwazRGO+kHskAwFNcJvu\nyniikepTsnrH1CwxrFVGtzMiYMHV8obFUc2P8WszDAbjlv/1CcN7YpvyRAjq3LLe\nPiGwzlXNkJP5+mOk3R5RnZDlxglS/5oNbFhD1Fu/dWX+nv0V+Cp9S6f1H22xMoy2\nI1+iK7X2JiCFNxtp8VgO1tMFPvLkq9xq5dOscwIDAQABAoIBAQCuEl60gDvdcNi5\nsodTBdGMDXx7oRSZ5AJNDjV0ofvuqGuHoAg3xVBIidP9qLLuPUjZ1+a8W+guzDUI\nQmzgZTFFwlf/pwXVV/Bvq6wGdYNcXLLYaOwnoGKvgMCbTwR9h3HiOmCVloClS8TC\nzMAqbNtzYunLTqNwL7q8ir7zaTyhG9uWHD01E5hPkC+ngP/zfYaLJ+sbolW9Qj2f\nZzxW3rmHoiKy5AkkdTDHhp5poGrXFlIVUMhr3yFYLjoDh3e0vPNuTexUkv8s8GbB\nAQbhDjsf2no6IK3f5JtEB/91K6GmfBpef+iyZUU1pG6EXx9/Keh69Iq5sKoNgIbg\nmTLsa9qhAoGBAPATr3yypGDLwJDfmBzBRCvtoME8PRNMX81fN1ZwIqzxZ1tB6F27\n6DzUuW1rDZmwLOsIFj+Quaas6NbIC0RFi8kvW40Pr86BKsrY2EQ/3Pu7O1a3S71q\nHGhAHHBxJGi/E4N/wSJVLWp6fB8DJqOdxuGW0AXC66lgSZuJ8+OguG3jAoGBANUf\nNewVgJZY5H5X8HiY6pZ0jWkyAq2U7rTYqaQuUOuJtNVeFLo6xj+Ne1+GnqWdRvUH\nGssaW7tSsgcfko7NcMdAu6pIhF+UxrDedswFeG7O0z+nFf1NCCHtYEIfDayPb+Ct\n2NWMxNowbCgx9ALOABhL1XrGuCxXYt+vTW4LIAwxAoGBAIc1rwn92pIhbsypARSA\nzJIo/PaXpJYv12zlCVeHRCA+vUUqM2JHKB7Kd7xmJHzAOiwMm+sk6Uoz69a7R40l\n1fpyz478nLkjCiTAR9z4Us77vgmypdeB4YndQacaMbVEmArhcraRXkivvyQANEzF\n2XLH61SzWOJFtm8BHPjAVd6dAoGBAJG3Qj4FwaKKasf7xn4eR57RV/KJ8AzQ3Jkn\n3m1UAZ3ZzJtqNQ/TqcLAMI9y0rv3mhFkZyxg/EFK3FBEhQdAbhC+MNHPvTpA1c0O\nffkm8F4K6aMG0eEbryjLTVpIMyg99kePdcck9V8dZoXhCa51PNlf2DmW70vZ/89i\n47UOxD2xAoGARoqgA9BMIlwfBcQ/7kBw6HbmadzV+Ob+rzoZjJiuSIQly9mv0rIQ\ngIGTFPcmPrZtb7FEGb4r101fLZwPNljIb430yaqz5fzGc3Wjv+Htjot9pSYFrlwr\n/C1/LCG0HfFj4srJSrGxPeMsohx3dhKj0Gr7o8fXi0d5ALhC/0g8Idk=\n-----END RSA PRIVATE KEY-----";

  BIO* public_bio = BIO_new(BIO_s_mem());
  BIO* private_bio = BIO_new(BIO_s_mem());
  BIO_write(public_bio, public_pem.c_str(), public_pem.length());
  BIO_write(private_bio, private_pem.c_str(), private_pem.length());

  RSA* rsa = RSA_new();
  PEM_read_bio_RSAPublicKey(public_bio, &rsa, nullptr, nullptr);
  PEM_read_bio_RSAPrivateKey(private_bio, &rsa, nullptr, nullptr);
  BIO_free(public_bio);
  BIO_free(private_bio);

  EVP_PKEY* keypair = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(keypair, rsa);

  PEM_write_PrivateKey(stdout, keypair, nullptr, nullptr, 0, 0, nullptr);
  PEM_write_PUBKEY(stdout, keypair);

  // ============================================
  /*
   * RSA: encrypt with public key
   */
  int pubkey_len = EVP_PKEY_size(keypair);
  int ek_len = 0, iv_len = 0;
  unsigned char* ek = new unsigned char[pubkey_len];
  unsigned char* iv = new unsigned char[EVP_MAX_IV_LENGTH];
  unsigned char* cipher = new unsigned char[msg256_len + EVP_MAX_IV_LENGTH];
  int cipher_len = EncryptEVP(msg256, msg256_len, keypair, &ek, &ek_len, &iv, &iv_len, &cipher);

  // ============================================
  /*
   * RSA: decrypt with private key
   */
  unsigned char* plain = new unsigned char[cipher_len + iv_len];
  int plain_len = DecryptEVP(&plain, keypair, ek, ek_len, iv, iv_len, cipher, cipher_len);
  EXPECT_STREQ(msg256, (const char*) plain);

  // ============================================
  /*
   * free
   */
  delete [] ek;  ek = nullptr;
  delete [] iv;  iv = nullptr;
  delete [] cipher;  cipher = nullptr;
  delete [] plain;  plain = nullptr;

  EVP_PKEY_free(keypair);
}

TEST(RSACrypting, EnvelopeFile) {
  // message of any length is possible for EVP
  const char* msg256 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";
  int msg256_len = strlen(msg256);

  // ============================================
  /*
   * RSA: read key pair
   */
  RSA* rsa = RSA_new();
  readKeysFromPEM("../test/data/public.pem", "../test/data/private.pem", &rsa);

  EVP_PKEY* keypair = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(keypair, rsa);

  PEM_write_PrivateKey(stdout, keypair, nullptr, nullptr, 0, 0, nullptr);
  PEM_write_PUBKEY(stdout, keypair);

  // ============================================
  /*
   * RSA: encrypt with public key
   */
  int pubkey_len = EVP_PKEY_size(keypair);
  int ek_len = 0, iv_len = 0;
  unsigned char* ek = new unsigned char[pubkey_len];
  unsigned char* iv = new unsigned char[EVP_MAX_IV_LENGTH];
  unsigned char* cipher = new unsigned char[msg256_len + EVP_MAX_IV_LENGTH];
  int cipher_len = EncryptEVP(msg256, msg256_len, keypair, &ek, &ek_len, &iv, &iv_len, &cipher);

  // ============================================
  /*
   * RSA: decrypt with private key
   */
  unsigned char* plain = new unsigned char[cipher_len + iv_len];
  int plain_len = DecryptEVP(&plain, keypair, ek, ek_len, iv, iv_len, cipher, cipher_len);
  EXPECT_STREQ(msg256, (const char*) plain);

  // ============================================
  /*
   * free
   */
  delete [] ek;  ek = nullptr;
  delete [] iv;  iv = nullptr;
  delete [] cipher;  cipher = nullptr;
  delete [] plain;  plain = nullptr;

  EVP_PKEY_free(keypair);
}

// @see http://stackoverflow.com/questions/9406840/rsa-encrypt-decrypt

TEST_F(RSACryptorTest, FixedKeys1) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  std::string public_pem = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAtaucDkZfJF65TPZ4p6PiFpG2EK+zOxG5O4KIj7WjlO5/KS5jEf+6\noqpjsb0dhlTh7BjDC9Eslb1TGuaUMA4pwX1GYYHShcpqasIXYMZM0rUryZqSB5Xe\nrh4JdTpZcIvqnwF+hNqIx0W4SkyR8C99IMOJ3TXbZdUaAP56Uqa8jNiND3/inJZD\nqEZMpZ88eu9Tb+7xWxkcLjRSOdQrmGscj0c0qQF3POXkzcy08OHYzozY12fhe40E\nOAqvyWWDQt6mZlwfXp9OQRuU+r4L9jHlNkosIYVdLKY6f+yP2kx7tJVYQ5ISSA70\no1vlO6kKXhnLMAar8ad5F5O1ZQRdJeMwPQIDAQAB\n-----END RSA PUBLIC KEY-----\n";

  std::string private_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtaucDkZfJF65TPZ4p6PiFpG2EK+zOxG5O4KIj7WjlO5/KS5j\nEf+6oqpjsb0dhlTh7BjDC9Eslb1TGuaUMA4pwX1GYYHShcpqasIXYMZM0rUryZqS\nB5Xerh4JdTpZcIvqnwF+hNqIx0W4SkyR8C99IMOJ3TXbZdUaAP56Uqa8jNiND3/i\nnJZDqEZMpZ88eu9Tb+7xWxkcLjRSOdQrmGscj0c0qQF3POXkzcy08OHYzozY12fh\ne40EOAqvyWWDQt6mZlwfXp9OQRuU+r4L9jHlNkosIYVdLKY6f+yP2kx7tJVYQ5IS\nSA70o1vlO6kKXhnLMAar8ad5F5O1ZQRdJeMwPQIDAQABAoIBAQCj1+vcq/butEdm\nc/uJJbKoLC4JioyYv3lRhH5pLaYkkZw5pc5P01WdkxJqoGbaWf+PkR2HsNUHD0K+\nRipr1Lov+S3ajt0xMMcdFYNEElQCzMZ7Al6lXLMCUbCx+zfi2y10zkIuy3EEV4rH\n55rPBeVSAUh7KzF9+92B/ACSPjJaywUgIykgBDLaW8acrJenGUt/s/KwDlSDfT79\nijq2I/D2KaF4K1DYwkZ2FB0Awyb5S5R7Ku+9YBbjyj0tDQ5kiJYLsCAIWos1KTS7\ndfp3U88r+Scqy8MHN4RRr6qkFIQgvQO60K6THfqtGciNP/FzGsrR2ciSf3lOTMYc\ngnktFBmBAoGBAOej/iLDj3r+F8QoRpMbUNy3juMPIlXV9Sw6KPe4CG4nqevv5wJl\ns/5B9ffhStooSR5u4LfXYNQ9aT2XXefk1zYmQftc/Lxph2BborBkl7WwpsK3QXp+\nWdK22z7NIECMnn5tEVVFGPdass44fcRDDpmtm9L3Jblx/SV+pFL4EFPtAoGBAMjG\nXZQSUFvI3HzCQCMOPYL0s9znWIKdOfdbX1GjkFysrVq7qfzvb6ZJeUIB9pOqtvKf\nwxFincSH9ibK0yiQ9bIDoQ8MyirdX04CFJWBg9fXlVAn31vqZVZ7PGtXy1vILdrr\n43mcOyaiKsjvBKUpjV0Yivl++NuF/voYbIp9C2ORAoGAI5I7ZHtDfU+ntqe4rr5z\nHHHTr2qTizrf+3qy79eC8+eDYIfmoaecjF70tqwSIo4tLE86kwCwDeegUaT89q9d\nnSMi3sbYyNYrw9BOm2fXJD+MXDpoA7eDc6hA4tP9L+xoKmH1V3LU8qcq7iAesBTc\nGR1f4HWzhVbL2QYpldQiLcECgYAOtHimH7FDB7MecBvCdYiLzuBdjZQt/NYCB+8z\nS4eHQh5wRs5seBz1UOxQqVQl/JrpqknfPBnSCyM8NB7DGdrk7t8c+xLTkOMqE3zu\ndk3xwRhuhn0VflVtwBjsw8FhN4gkQKKohYjPi5EWpmrwrdpstx92ppYTffzu1Fse\nyYnMAQKBgCynG+Otqwiowe8DfgrOyPV7cOG59FK49j6pZACqBzXm0q3dbBID+OZA\nGr1pv0nnMrY4ITM75jYMlL7gSCyJzGwvD251o1nHfBhuDe20mBp9u5DHYe95ENaV\nQCP05gaTTfYQobvfUZo2ikMEap3bX1ZXMH1rNigIGlf+0PYk/qH0\n-----END RSA PRIVATE KEY-----\n";

  auto keypair = std::make_pair<secure::Key, secure::Key>(secure::Key(800, public_pem), secure::Key(800, private_pem));

  unsigned char* cipher = new unsigned char[input.length() + EVP_MAX_IV_LENGTH];

  secure::RSACryptorRaw cryptor;
  cryptor.setKeypair(keypair);
  int cipher_len = cryptor.encrypt(input, &cipher);

  unsigned char* plain = new unsigned char[cipher_len + EVP_MAX_IV_LENGTH];

  int plain_len = cryptor.decrypt(cipher, cipher_len, &plain);
  std::string output((const char*) plain);
  EXPECT_EQ(input.length(), plain_len);
  EXPECT_STREQ(input.c_str(), output.c_str());

  delete [] cipher;  cipher = nullptr;
  delete [] plain;   plain  = nullptr;
}

TEST_F(RSACryptorTest, FixedKeys2) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  std::string public_pem = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAoYU2rBQsP8oXiCiIY206MMNnhGyl9X7VAXTAwfC08b8jGx5jA/iz\naKZlOJM79Y4agSm4LzjGgK3Br1ONL23qpzvR1nL5NbqCEhDNvUaUgb/rrKkPXa0t\nuEaxE17ZVQAK7XwWpLN3tvZIh8WwzjOIqVpAKBQbOs029l6IxGuag5lBl3QyzSjc\nMgI+LPGihmehaZIkmuw/+bNMQ474MvEJQ8Bhsz76oMvGm1lPIovgvKdtHZq52KI0\nJDymYCA3R42CfICw1dwJkqpklYHjKxbv7jbefsD35iIYghpKm6QiE9v6b0pnpR/2\nAaxH/6C/NUD+ptGkJjq7Zj3ISFbOzxVyqwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

  std::string private_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAoYU2rBQsP8oXiCiIY206MMNnhGyl9X7VAXTAwfC08b8jGx5j\nA/izaKZlOJM79Y4agSm4LzjGgK3Br1ONL23qpzvR1nL5NbqCEhDNvUaUgb/rrKkP\nXa0tuEaxE17ZVQAK7XwWpLN3tvZIh8WwzjOIqVpAKBQbOs029l6IxGuag5lBl3Qy\nzSjcMgI+LPGihmehaZIkmuw/+bNMQ474MvEJQ8Bhsz76oMvGm1lPIovgvKdtHZq5\n2KI0JDymYCA3R42CfICw1dwJkqpklYHjKxbv7jbefsD35iIYghpKm6QiE9v6b0pn\npR/2AaxH/6C/NUD+ptGkJjq7Zj3ISFbOzxVyqwIDAQABAoIBADBbdrvcKkdK1PLB\n19uUpxhUWFiwQpuWRmVyNAecbj/2Tqde2JwmyGfrcWCXzBq/WbYT7H3OzLdXziYU\nqK9rhBZfdXpz36KzXR/VghNJ30pdUEzYLK6KG6cRGxDGk+C764mgXhMfXBcd8ycb\nC80gZqj1SUH2ixR2vh7SvLW51X/SV6s/KlPa3kTt0MwqqmAw4iGqEabqPjd/UYKF\na1fjMba38Ew6zSB1I0loqPfGGb8DoLVzmSQPamEElx0c7pYfYnTa+8esw6qTtJ7n\nbboNZ/Y3wUhkxjs4yulrWfQuyWcmRN2AfIFBm82jb8USxCRm8AnFpZMLW9K/aD8u\nKe46qOECgYEAy8tQIyTOF5PZhRZET0SGa4Df0Z2bnK/RWmFT/EM/ZnWCXKy/b12Q\nDf4Ik1vNA3dgBpBEL1gVviEis3/kSnSWUJ60IQzCgqDvsBrKm3ypK2QbIhK+YGTC\nYWdmJKMZ8Z+8bRfUX2JOntePzI5X0Yl853MmOKkFUWNuUGwnz4fjaHECgYEAyuWc\netB8PuLdYPRlWXuVlaR7o5h5ZU31m2HwEZCL3pArAnPv7aYGCPp5MCbxJ5lqbEq2\n/dggqK6U6tRi92RCllcRRfFN4ZroeN8gfBlSuHnG4h0MJbUUbk+bWotWdlyQb8rp\nW1YPmeXe/DZRP+6AaKjZ3RHD9P0lGOuw/5y5utsCgYEAr/tcs0xoD6Ij9zIYQN8q\nuJCsNiXEp9SHk2Vykec8S2zz6rVeBnwkFoEkxKNEcVbXfDN+PefxtqKEhb7N06HD\n39B8OgH7wbPZ5xfrl8NZjle+uni3HyRDWrtgUAjsMWO/4fDu+oM44x/AVGMi4JW6\nX19nRQxnxDV5oEcVRbfRn3ECgYAt/WO9ttoiyvuRCXSbltauJ61axKnnm4crZESt\nRo1dsmH9WVguDu7ZRCUKFBmfdzfXOgxGd6HXelMI84FHQDOTrkKdDvgvRhShqTnM\nx1SnufqpsBnbxjLOWj8FhAXiKFMY8+53JIe+w4sKsikyi5YRowxW/rrjIioxfuMM\n3XJ/9wKBgDFV2pkz/k0P6VigmmHunEJVDM3p1pMp1ufTdFmOu754zC5SOBFJ4s+a\neRqfJr/UVBRlSQ9aBiMgFYbmTvdc2a1EMWjvSxbFBMjgKnkaFGPu+IxhwbLxh5YR\n5VY7pEd+NFlu+4DSKm7NFgI6toyQpE5J12YL51P4DV4IVCWET9QY\n-----END RSA PRIVATE KEY-----\n";

  auto keypair = std::make_pair<secure::Key, secure::Key>(secure::Key(800, public_pem), secure::Key(800, private_pem));

  unsigned char* cipher = new unsigned char[input.length() + EVP_MAX_IV_LENGTH];

  secure::RSACryptorRaw cryptor;
  cryptor.setKeypair(keypair);
  int cipher_len = cryptor.encrypt(input, &cipher);

  unsigned char* plain = new unsigned char[cipher_len + EVP_MAX_IV_LENGTH];

  int plain_len = cryptor.decrypt(cipher, cipher_len, &plain);
  std::string output((const char*) plain);
  EXPECT_EQ(input.length(), plain_len);
  EXPECT_STREQ(input.c_str(), output.c_str());

  delete [] cipher;  cipher = nullptr;
  delete [] plain;   plain  = nullptr;
}

TEST_F(RSACryptorTest, CompleteRaw) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  unsigned char* cipher = new unsigned char[input.length() + EVP_MAX_IV_LENGTH];

  secure::RSACryptorRaw cryptor;
  cryptor.setKeypair(m_key_pair);
  int cipher_len = cryptor.encrypt(input, &cipher);

  unsigned char* plain = new unsigned char[cipher_len + EVP_MAX_IV_LENGTH];

  int plain_len = cryptor.decrypt(cipher, cipher_len, &plain);
  std::string output((const char*) plain);
  EXPECT_EQ(input.length(), plain_len);
  EXPECT_STREQ(input.c_str(), output.c_str());

  delete [] cipher;  cipher = nullptr;
  delete [] plain;   plain  = nullptr;
}

TEST_F(RSACryptorTest, CompleteWrapped) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  secure::RSACryptorWrapped cryptor;
  cryptor.setKeypair(m_key_pair);
  std::string cipher = cryptor.encrypt(input);
  std::string output = cryptor.decrypt(cipher);
  EXPECT_STREQ(input.c_str(), output.c_str());
}

TEST(RSACrypting, FixedKeys) {
  std::string input = "hello";

  std::string public_pem = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAoYU2rBQsP8oXiCiIY206MMNnhGyl9X7VAXTAwfC08b8jGx5jA/iz\naKZlOJM79Y4agSm4LzjGgK3Br1ONL23qpzvR1nL5NbqCEhDNvUaUgb/rrKkPXa0t\nuEaxE17ZVQAK7XwWpLN3tvZIh8WwzjOIqVpAKBQbOs029l6IxGuag5lBl3QyzSjc\nMgI+LPGihmehaZIkmuw/+bNMQ474MvEJQ8Bhsz76oMvGm1lPIovgvKdtHZq52KI0\nJDymYCA3R42CfICw1dwJkqpklYHjKxbv7jbefsD35iIYghpKm6QiE9v6b0pnpR/2\nAaxH/6C/NUD+ptGkJjq7Zj3ISFbOzxVyqwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

  std::string private_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAoYU2rBQsP8oXiCiIY206MMNnhGyl9X7VAXTAwfC08b8jGx5j\nA/izaKZlOJM79Y4agSm4LzjGgK3Br1ONL23qpzvR1nL5NbqCEhDNvUaUgb/rrKkP\nXa0tuEaxE17ZVQAK7XwWpLN3tvZIh8WwzjOIqVpAKBQbOs029l6IxGuag5lBl3Qy\nzSjcMgI+LPGihmehaZIkmuw/+bNMQ474MvEJQ8Bhsz76oMvGm1lPIovgvKdtHZq5\n2KI0JDymYCA3R42CfICw1dwJkqpklYHjKxbv7jbefsD35iIYghpKm6QiE9v6b0pn\npR/2AaxH/6C/NUD+ptGkJjq7Zj3ISFbOzxVyqwIDAQABAoIBADBbdrvcKkdK1PLB\n19uUpxhUWFiwQpuWRmVyNAecbj/2Tqde2JwmyGfrcWCXzBq/WbYT7H3OzLdXziYU\nqK9rhBZfdXpz36KzXR/VghNJ30pdUEzYLK6KG6cRGxDGk+C764mgXhMfXBcd8ycb\nC80gZqj1SUH2ixR2vh7SvLW51X/SV6s/KlPa3kTt0MwqqmAw4iGqEabqPjd/UYKF\na1fjMba38Ew6zSB1I0loqPfGGb8DoLVzmSQPamEElx0c7pYfYnTa+8esw6qTtJ7n\nbboNZ/Y3wUhkxjs4yulrWfQuyWcmRN2AfIFBm82jb8USxCRm8AnFpZMLW9K/aD8u\nKe46qOECgYEAy8tQIyTOF5PZhRZET0SGa4Df0Z2bnK/RWmFT/EM/ZnWCXKy/b12Q\nDf4Ik1vNA3dgBpBEL1gVviEis3/kSnSWUJ60IQzCgqDvsBrKm3ypK2QbIhK+YGTC\nYWdmJKMZ8Z+8bRfUX2JOntePzI5X0Yl853MmOKkFUWNuUGwnz4fjaHECgYEAyuWc\netB8PuLdYPRlWXuVlaR7o5h5ZU31m2HwEZCL3pArAnPv7aYGCPp5MCbxJ5lqbEq2\n/dggqK6U6tRi92RCllcRRfFN4ZroeN8gfBlSuHnG4h0MJbUUbk+bWotWdlyQb8rp\nW1YPmeXe/DZRP+6AaKjZ3RHD9P0lGOuw/5y5utsCgYEAr/tcs0xoD6Ij9zIYQN8q\nuJCsNiXEp9SHk2Vykec8S2zz6rVeBnwkFoEkxKNEcVbXfDN+PefxtqKEhb7N06HD\n39B8OgH7wbPZ5xfrl8NZjle+uni3HyRDWrtgUAjsMWO/4fDu+oM44x/AVGMi4JW6\nX19nRQxnxDV5oEcVRbfRn3ECgYAt/WO9ttoiyvuRCXSbltauJ61axKnnm4crZESt\nRo1dsmH9WVguDu7ZRCUKFBmfdzfXOgxGd6HXelMI84FHQDOTrkKdDvgvRhShqTnM\nx1SnufqpsBnbxjLOWj8FhAXiKFMY8+53JIe+w4sKsikyi5YRowxW/rrjIioxfuMM\n3XJ/9wKBgDFV2pkz/k0P6VigmmHunEJVDM3p1pMp1ufTdFmOu754zC5SOBFJ4s+a\neRqfJr/UVBRlSQ9aBiMgFYbmTvdc2a1EMWjvSxbFBMjgKnkaFGPu+IxhwbLxh5YR\n5VY7pEd+NFlu+4DSKm7NFgI6toyQpE5J12YL51P4DV4IVCWET9QY\n-----END RSA PRIVATE KEY-----\n";

  auto keypair = std::make_pair<secure::Key, secure::Key>(secure::Key(700, public_pem), secure::Key(700, private_pem));

  secure::RSACryptor cryptor;

  bool encrypted = false;
  std::string cipher = cryptor.encrypt(input, keypair.first, encrypted);
  EXPECT_TRUE(encrypted);

  bool decrypted = false;
  std::string output = cryptor.decrypt(cipher, keypair.second, decrypted);
  EXPECT_TRUE(decrypted);

  EXPECT_STREQ(input.c_str(), output.c_str());
}

TEST_F(RSACryptorTest, Complete) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  secure::RSACryptor cryptor;

  bool encrypted = false;
  std::string cipher = cryptor.encrypt(input, m_key_pair.first, encrypted);
  EXPECT_TRUE(encrypted);

  bool decrypted = false;
  std::string output = cryptor.decrypt(cipher, m_key_pair.second, decrypted);
  EXPECT_TRUE(decrypted);

  EXPECT_STREQ(input.c_str(), output.c_str());
}

}

#endif  // SECURE

