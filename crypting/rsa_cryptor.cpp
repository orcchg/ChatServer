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

#include <cstdio>
#include <cstring>
#include "rsa_cryptor.h"
#include "common.h"
#include "logger.h"

// @see https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope
// @see http://hayageek.com/rsa-encryption-decryption-openssl-c/

namespace secure {

RSACryptor::RSACryptor() {
}

RSACryptor::~RSACryptor() {
}

std::string RSACryptor::encrypt(const std::string& source, const Key& public_key) {
  TRC("encrypt(%s)", source.c_str());
  if (public_key != Key::EMPTY) {
    //
  }
  WRN("Public key wasn't provided, source hasn't been encrypted");
  return source;  // not encrypted
}

std::string RSACryptor::decrypt(const std::string& source, const Key& private_key) {
  TRC("decrypt(%s)", source.c_str());
  if (private_key != Key::EMPTY) {
    //
  }
  WRN("Private key wasn't provided, source hasn't been decrypted");
  return source;  // not decrypted
}

/* Private */
// ----------------------------------------------------------------------------

}

#endif  // SECURE

