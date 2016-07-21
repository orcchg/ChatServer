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

#ifndef CHAT_SERVER_AES_CRYPTOR__H__
#define CHAT_SERVER_AES_CRYPTOR__H__

#if SECURE

#include <openssl/evp.h>
#include "api/icryptor.h"
#include "sym_key.h"

#define IV_LENGTH SHA256_DIGEST_LENGTH >> 1

namespace secure {

class AESCryptor : public ICryptor {
public:
  AESCryptor();  // generate key and IV
  AESCryptor(unsigned char* raw, unsigned char* iv);
  AESCryptor(const SymmetricKey& key, unsigned char* iv);  // use previously generated IV
  virtual ~AESCryptor();

  std::string encrypt(const std::string& source) override;
  std::string decrypt(const std::string& source) override;

  inline const SymmetricKey& getKey() const { return m_key; }
  inline SymmetricKey getKeyCopy() const { return m_key; }
  unsigned char* getIVCopy() const;

  inline unsigned char* getRaw() const { return m_raw; }
  inline size_t getRawLength() const { return m_raw_length; }
  inline size_t getIVLength() const { return IV_LENGTH; }

private:
  SymmetricKey m_key;
  unsigned char* m_iv;
  unsigned char* m_raw;
  size_t m_raw_length;

  void init();
  void release();
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_AES_CRYPTOR__H__

