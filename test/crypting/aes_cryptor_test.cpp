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
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string>
#include <cstring>
#include "common.h"
#include "crypting/aes_cryptor.h"
#include "logger.h"

namespace test {

/* Fixture */
// ----------------------------------------------------------------------------
/* Fixed key and IV */
// ----------------------------------------------
class AESCryptorFixedTest : public ::testing::Test {
protected:
  AESCryptorFixedTest();

protected:
  secure::AESCryptor m_cryptor;
};

AESCryptorFixedTest::AESCryptorFixedTest()
  : m_cryptor((unsigned char*) "01234567890123456789012345678901",
              (unsigned char*) "01234567890123456") {
}

/* Tests */
// ----------------------------------------------------------------------------
/* Fixed key and IV */
// ----------------------------------------------
TEST_F(AESCryptorFixedTest, GetCipher1) {
  std::string input = "hello";
  std::string hex_cipher = "55cc8e112f7fd1889f5ef9d92a8f1ce2";
  std::string output = m_cryptor.encrypt(input);
  EXPECT_STREQ(hex_cipher.c_str(), output.c_str());
}

TEST_F(AESCryptorFixedTest, GetCipher2) {
  std::string input = "world";
  std::string hex_cipher = "b4b3c20dbdc5727876708b4c7533cd9c";
  std::string output = m_cryptor.encrypt(input);
  EXPECT_STREQ(hex_cipher.c_str(), output.c_str());
}

TEST_F(AESCryptorFixedTest, DecryptCipher1) {
  std::string hex_cipher = "55cc8e112f7fd1889f5ef9d92a8f1ce2";
  std::string output = m_cryptor.decrypt(hex_cipher);
  EXPECT_STREQ("hello", output.c_str());
}

TEST_F(AESCryptorFixedTest, DecryptCipher2) {
  std::string hex_cipher = "b4b3c20dbdc5727876708b4c7533cd9c";
  std::string output = m_cryptor.decrypt(hex_cipher);
  EXPECT_STREQ("world", output.c_str());
}

/* Random key and IV */
// ----------------------------------------------
TEST(AESCryptorTest, Complete) {
  secure::AESCryptor cryptor;  // generate key and IV
  std::string input = "hello";
  std::string cipher_hex = cryptor.encrypt(input);
  std::string output = cryptor.decrypt(cipher_hex);
  EXPECT_STREQ(input.c_str(), output.c_str());
}

TEST(AESCryptor, RawComplete) {
  const char* msg256 = "hello";//"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna. Maecenas quis mi est blandit";
  int msg256_len = strlen(msg256);

  // ============================================
  /*
   * AES: generate key
   */
  unsigned char* aesKey  = new unsigned char[AES_KEYLEN / 8];
  unsigned char* aesIV   = new unsigned char[AES_KEYLEN / 8];
  unsigned char* aesPass = new unsigned char[AES_KEYLEN / 8];
  unsigned char* aesSalt = new unsigned char[8];

  memset(aesKey, 0, AES_KEYLEN / 8);
  memset(aesIV, 0, AES_KEYLEN / 8);
  memset(aesPass, 0, AES_KEYLEN / 8);
  memset(aesSalt, 0, 8);

  RAND_bytes(aesPass, AES_KEYLEN / 8);
  RAND_bytes(aesSalt, 8);
  EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, AES_KEYLEN / 8, AES_ROUNDS, aesKey, aesIV);

  delete [] aesPass;  aesPass = nullptr;
  delete [] aesSalt;  aesSalt = nullptr;

  std::string aesKey_hex = common::bin2hex(aesKey, AES_KEYLEN / 8);
  std::string aesIV_hex  = common::bin2hex(aesIV,  AES_KEYLEN / 8);
  TTY("AES KEY: %s", aesKey_hex.c_str());
  TTY("AES IV:  %s", aesIV_hex.c_str());

  // ============================================
  /*
   * AES: encrypt
   */
  unsigned char* cipher = new unsigned char[msg256_len + AES_BLOCK_SIZE];
  memset(cipher, 0, msg256_len + AES_BLOCK_SIZE);
  int block_len = 0;
  int cipher_len = 0;

  EVP_CIPHER_CTX* aes_enc_ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(aes_enc_ctx, EVP_aes_256_cbc(), nullptr, aesKey, aesIV);
  EVP_EncryptUpdate(aes_enc_ctx, cipher, (int*) &block_len, (unsigned char*) msg256, msg256_len);
  cipher_len += block_len;
  EVP_EncryptFinal_ex(aes_enc_ctx, cipher + cipher_len, (int*) &block_len);
  cipher_len += block_len;
  EVP_CIPHER_CTX_free(aes_enc_ctx);
  TTY("AES Cipher[%i]: %.*s", cipher_len, cipher_len, cipher);

  // ============================================
  /*
   * AES: decrypt
   */
  unsigned char* plain = new unsigned char[cipher_len];
  memset(plain, 0, cipher_len);
  int block_len_x = 0;
  int plain_len = 0;

  EVP_CIPHER_CTX* aes_dec_ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(aes_dec_ctx, EVP_aes_256_cbc(), nullptr, aesKey, aesIV);
  EVP_DecryptUpdate(aes_dec_ctx, plain, (int*) &block_len_x, cipher, cipher_len);
  plain_len += block_len_x;
  EVP_DecryptFinal_ex(aes_dec_ctx, plain + plain_len, (int*) &block_len_x);
  plain_len += block_len_x;
  EVP_CIPHER_CTX_free(aes_dec_ctx);
  TTY("AES Plain[%i]: %.*s", plain_len, plain_len, plain);
  strncpy((char*) plain, (const char*) plain, plain_len);
  EXPECT_STREQ(msg256, (const char*) plain);

  // ============================================
  /*
   * free
   */
  delete [] cipher;   cipher  = nullptr;
  delete [] plain;    plain   = nullptr;
  delete [] aesKey;   aesKey  = nullptr;
  delete [] aesIV;    aesIV   = nullptr;
}

}

#endif  // SECURE

