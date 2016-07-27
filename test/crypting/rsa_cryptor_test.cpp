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

ID_t RSACryptorTest::s_id = 1000;

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
  FILE* prifile = fopen("id_900_private.pem", "rt");
  FILE* pubfile = fopen("id_900_public.pem", "rt");
  PEM_read_RSAPrivateKey(prifile, &rsa, nullptr, nullptr);
  PEM_read_RSAPublicKey(pubfile, &rsa, nullptr, nullptr);

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

TEST(RSACryptingFixedKeys, Complete) {
  //secure::RSACryptor cryptor;
  //cryptor.setPublicKey("../test/crypting/public.pem");
  //cryptor.setPrivateKey("../test/crypting/private.pem");

  //std::string input = "hello";
  //std::string cipher = cryptor.encrypt(input);
  //std::string output = cryptor.decrypt(cipher);
  //EXPECT_STREQ(input.c_str(), output.c_str());
}

TEST_F(RSACryptorTest, Complete) {

}

}

#endif  // SECURE

