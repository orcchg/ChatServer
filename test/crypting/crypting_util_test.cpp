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
#include "crypting/crypting_util.h"
#include "crypting/random_util.h"
#include "crypting/rsa_cryptor.h"
#include "logger.h"

namespace test {

/* Fixture */
// ----------------------------------------------------------------------------
static common::Dictionary s_dictionary;

class CryptingUtilTest : public ::testing::Test {
protected:
  CryptingUtilTest() { --s_id; }
  void SetUp() override;
  void TearDown() override;

protected:
  static ID_t s_id;
  std::pair<secure::Key, secure::Key> m_key_pair;
  Message m_message;
};

ID_t CryptingUtilTest::s_id = 800;

void CryptingUtilTest::SetUp() {
  bool accessible = false;
  const size_t size = 80;
  std::string input = secure::random::generateString(size);
  secure::random::generateKeyPair(s_id, input.c_str(), size);
  m_key_pair = secure::random::loadKeyPair(s_id, &accessible);
  m_message = common::generateMessage(s_dictionary, s_id);
}

void CryptingUtilTest::TearDown() {
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
TEST_F(CryptingUtilTest, FixedMessage) {
  std::string text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  Message message = Message::Builder(100).setLogin("login").setEmail("email@ya.ru").setChannel(0)
      .setDestId(0).setTimestamp(1000000000).setSize(text.length())
      .setEncrypted(false).setMessage(text)
      .build();
  Message init_message = message;
  DBG("Message: %s", message.getMessage().c_str());

  secure::RSACryptor cryptor;

  message.encrypt(cryptor, m_key_pair.first);
  EXPECT_TRUE(message.isEncrypted());

  message.decrypt(cryptor, m_key_pair.second);
  EXPECT_FALSE(message.isEncrypted());

  EXPECT_EQ(init_message, message);
}

TEST_F(CryptingUtilTest, DISABLED_SeparateCryptorsRaw) {
  std::string small = "a";
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  bool encrypted = false;
  secure::RSACryptor cryptor_one;
  std::string cipher = cryptor_one.encrypt(input, m_key_pair.first, encrypted);
  EXPECT_TRUE(encrypted);

  int ek_len = cryptor_one.getEKlength();
  int iv_len = cryptor_one.getIVlength();
  unsigned char* ek = new unsigned char[ek_len];
  unsigned char* iv = new unsigned char[iv_len];
  cryptor_one.getEK(ek);
  cryptor_one.getIV(iv);

  bool decrypted = false;
  secure::RSACryptor cryptor_two;
  cryptor_two.setEK(ek_len, ek);
  cryptor_two.setIV(iv_len, iv);

  std::string output = cryptor_two.decrypt(cipher, m_key_pair.second, decrypted);
  EXPECT_TRUE(decrypted);

  delete [] ek;  ek = nullptr;
  delete [] iv;  iv = nullptr;

  EXPECT_STREQ(input.c_str(), output.c_str());
}

TEST_F(CryptingUtilTest, DISABLED_SeparateCryptors) {
  std::string text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  Message message = Message::Builder(100).setLogin("login").setEmail("email@ya.ru").setChannel(0)
      .setDestId(0).setTimestamp(1000000000).setSize(text.length())
      .setEncrypted(false).setMessage(text)
      .build();
  Message init_message = message;
  DBG("Message: %s", message.getMessage().c_str());

  secure::RSACryptor cryptor_one, cryptor_two;

  message.encrypt(cryptor_one, m_key_pair.first);
  EXPECT_TRUE(message.isEncrypted());

  message.decrypt(cryptor_two, m_key_pair.second);
  EXPECT_FALSE(message.isEncrypted());

  EXPECT_EQ(init_message, message);
}

TEST_F(CryptingUtilTest, DISABLED_RandomMessage) {
  Message init_message = m_message;  // copy
  DBG("Message: %s", m_message.getMessage().c_str());

  secure::RSACryptor cryptor;

  m_message.encrypt(cryptor, m_key_pair.first);
  EXPECT_TRUE(m_message.isEncrypted());

  m_message.decrypt(cryptor, m_key_pair.second);
  EXPECT_FALSE(m_message.isEncrypted());

  EXPECT_EQ(init_message, m_message);
}

TEST_F(CryptingUtilTest, DISABLED_Complete) {
  std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus scelerisque felis odio, eu hendrerit eros laoreet at. Fusce ac rutrum nisl, quis feugiat tortor. Vestibulum non urna est. Maecenas quis mi at est blandit tempor. Nullam ut quam porttitor, convallis nisl vitae, pulvinar quam. In hac habitasse platea dictumst. Aenean vehicula mauris odio, eu mattis augue tristique in. Morbi nec magna sit amet elit tempor sagittis. Suspendisse id tempor velit. Suspendisse nec velit orci. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vivamus commodo ullamcorper convallis. Nunc congue lobortis dictum.";

  bool encrypted = false;
  std::string chunk = secure::encryptAndPack(m_key_pair.first, input, encrypted);
  EXPECT_TRUE(encrypted);

  bool decrypted = false;
  std::string output = secure::unpackAndDecrypt(m_key_pair.second, chunk, decrypted);
  EXPECT_TRUE(decrypted);

  EXPECT_STREQ(input.c_str(), output.c_str());
}

}

#endif  // SECURE

