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
#include "common.h"
#include "crypting/aes_cryptor.h"

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

}

#endif  // SECURE

