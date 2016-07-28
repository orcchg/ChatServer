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

#ifndef CHAT_SERVER_RSA_CRYPTOR__H__
#define CHAT_SERVER_RSA_CRYPTOR__H__

#if SECURE

#include <string>
#include "api/icryptor.h"
#include "includes.h"

// @see https://shanetully.com/2012/06/openssl-rsa-aes-and-c/
// @see https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/

namespace secure {

class RSACryptor : public IAsymmetricCryptor {
public:
  RSACryptor();
  virtual ~RSACryptor();

  std::string encrypt(const std::string& source, const Key& public_key) override;
  std::string decrypt(const std::string& source, const Key& private_key) override;

private:
  //Crypto m_crypto;
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_RSA_CRYPTOR__H__

