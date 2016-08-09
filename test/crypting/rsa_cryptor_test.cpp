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
  EVP_SealInit(rsa_enc_ctx, EVP_aes_256_cbc(), ek, (int*) ek_len, *iv, &keypair, 1);
  EVP_SealUpdate(rsa_enc_ctx, *cipher, (int*) &block_len, (unsigned char*) msg256, msg256_len);
  cipher_len += block_len;
  EVP_SealFinal(rsa_enc_ctx, *cipher + cipher_len, (int*) &block_len);
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
  EVP_OpenUpdate(rsa_dec_ctx, *plain, (int*) &block_len, cipher, cipher_len);
  plain_len += block_len;
  EVP_OpenFinal(rsa_dec_ctx, *plain + plain_len, (int*) &block_len);
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

TEST_F(RSACryptorTest, Complete) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  secure::RSACryptor cryptor;
  std::string cipher = cryptor.encrypt(input, m_key_pair.first);
  std::string output = cryptor.decrypt(cipher, m_key_pair.second);
  EXPECT_STREQ(input.c_str(), output.c_str());
}

}

#endif  // SECURE

