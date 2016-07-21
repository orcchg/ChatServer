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

#ifndef CHAT_SERVER_SYM_KEY__H__
#define CHAT_SERVER_SYM_KEY__H__

#if SECURE

#include <string>
#include <openssl/sha.h>

namespace secure {

struct SymmetricKey {
  unsigned char key[SHA256_DIGEST_LENGTH];

  SymmetricKey();
  SymmetricKey(unsigned char* i_key);
  SymmetricKey(const std::string& source);

  inline size_t getLength() const { return SHA256_DIGEST_LENGTH; }

private:
  void generate(const std::string& source);
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_SYM_KEY__H__

