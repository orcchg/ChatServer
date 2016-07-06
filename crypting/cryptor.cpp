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

#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/sha.h>
#include "cryptor.h"
#include "logger.h"

namespace secure {

Cryptor::Cryptor() {
}

Cryptor::~Cryptor() {
}

std::string Cryptor::encrypt(const std::string& source) {
  char input[source.length()];
  unsigned char buffer[SHA256_DIGEST_LENGTH];
  strncpy(input, source.c_str(), source.length());
  SHA256((unsigned char*) input, source.length(), buffer);

  std::ostringstream oss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    oss << std::hex << (int) buffer[i];
  }
  return oss.str();
}

std::string Cryptor::decrypt(const std::string& source) {
  ERR("Operation not supported!");
  throw UnsupportedOperationException();
}

}

#endif  // SECURE

