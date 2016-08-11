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
#include "logger.h"

namespace test {

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

/* Tests */
// ----------------------------------------------------------------------------
TEST_F(EVPfixture, FileKeys) {

}

TEST_F(EVPfixture, RawKeys) {

}

TEST_F(EVPfixture, Separate) {

}

}

#endif  // SECURE

