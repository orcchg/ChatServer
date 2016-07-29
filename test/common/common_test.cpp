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

#include <string>
#include <gtest/gtest.h>
#include "common.h"

namespace test {

TEST(RestoreStrippedPEM, InMemory1) {
  std::string pem_stripped = "-----BEGIN RSA PUBLIC KEY-----MIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASavjS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4eP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7xyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOGi11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB-----END RSA PUBLIC KEY-----";

  std::string pem_normal = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASav\njS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4\neP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7x\nyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOG\ni11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZ\nF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB\n-----END RSA PUBLIC KEY-----";

  std::string pem_restored = common::restoreStrippedInMemoryPEM(pem_stripped);
  EXPECT_STREQ(pem_normal.c_str(), pem_restored.c_str());
}

TEST(RestoreStrippedPEM, DISABLED_InMemory2) {
  std::string pem_normal = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASav\njS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4\neP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7x\nyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOG\ni11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZ\nF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB\n-----END RSA PUBLIC KEY-----";

  std::string pem_stripped = common::preparse(pem_normal, common::PreparseLeniency::STRICT);
  std::string pem_restored = common::restoreStrippedInMemoryPEM(pem_stripped);
  EXPECT_STREQ(pem_normal.c_str(), pem_restored.c_str());
}

}

