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

#include <cstring>
#include "random_util.h"
#include "sym_key.h"

namespace secure {

SymmetricKey::SymmetricKey() {
  random::setRandomSeed();
  int length = rand() % 71 + 10;
  std::string source = random::generateString(length);
  generate(source);
}

SymmetricKey::SymmetricKey(const std::string& source) {
  generate(source);
}

void SymmetricKey::generate(const std::string& source) {
  char input[source.length()];
  strncpy(input, source.c_str(), source.length());
  SHA256((unsigned char*) input, source.length(), key);
}

}

#endif  // SECURE
