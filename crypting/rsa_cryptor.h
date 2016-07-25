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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "api/icryptor.h"

namespace secure {

class RSACryptor : public ICryptor {
public:
  RSACryptor();
  virtual ~RSACryptor();

  std::string encrypt(const std::string& source) override;
  std::string decrypt(const std::string& source) override;

  inline void setPublicKey(const std::string& public_key_filename) { m_public_key_filename = public_key_filename; }
  inline void setPrivateKey(const std::string& private_key_filename) { m_private_key_filename = private_key_filename; }

private:
  std::string m_public_key_filename;
  std::string m_private_key_filename;
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_RSA_CRYPTOR__H__

