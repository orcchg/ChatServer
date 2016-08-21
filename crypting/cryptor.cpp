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
 *
 *   This program and text files composing it, and/or compiled binary files
 *   (object files, shared objects, binary executables) obtained from text
 *   files of this program using compiler, as well as other files (text, images, etc.)
 *   composing this program as a software project, or any part of it,
 *   cannot be used by 3rd-parties in any commercial way (selling for money or for free,
 *   advertising, commercial distribution, promotion, marketing, publishing in media, etc.).
 *   Only the original author - Maxim Alov - has right to do any of the above actions.
 */

#if SECURE

#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/sha.h>
#include "common.h"
#include "cryptor.h"
#include "exception.h"
#include "logger.h"
#include "sym_key.h"

namespace secure {

Cryptor::Cryptor() {
}

Cryptor::~Cryptor() {
}

std::string Cryptor::encrypt(const std::string& source) {
  SymmetricKey key(source);
  return common::bin2hex(key.key, key.getLength());
}

std::string Cryptor::decrypt(const std::string& source) {
  ERR("Operation not supported!");
  throw UnsupportedOperationException();
}

}

#endif  // SECURE

