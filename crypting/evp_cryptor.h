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

#ifndef CHAT_SERVER_EVP_CRYPTOR__H__
#define CHAT_SERVER_EVP_CRYPTOR__H__

#if SECURE

#include <string>
#include <cstring>
#include "api/icryptor.h"
#include "includes.h"

namespace secure {

class EVPCryptor : public IAsymmetricCryptor {
public:
  EVPCryptor();
  virtual ~EVPCryptor();

  std::string encrypt(const std::string& source, const secure::Key& public_key, bool& encrypted) override;
  std::string decrypt(const std::string& source, const secure::Key& private_key, bool& decrypted) override;

  inline int getEKlength() const override { return m_ek_len; }
  inline int getIVlength() const override { return m_iv_len; }
  void getEK(unsigned char* ek) const override { memcpy(ek, m_ek, m_ek_len); }
  void getIV(unsigned char* iv) const override { memcpy(iv, m_iv, m_iv_len); }

  void setEK(int ek_len, unsigned char* ek) override {
    if (m_ek != nullptr) { delete [] m_ek;  m_ek = nullptr; }
    m_ek = new unsigned char[ek_len];
    memcpy(m_ek, ek, ek_len);
  }
  void setIV(int iv_len, unsigned char* iv) override {
    if (m_iv != nullptr) { delete [] m_iv;  m_iv = nullptr; }
    m_iv = new unsigned char[iv_len];
    memcpy(m_iv, iv, iv_len);
  }

private:
  int m_ek_len;
  int m_iv_len;
  int m_cipher_len;
  unsigned char* m_ek;
  unsigned char* m_iv;
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_EVP_CRYPTOR__H__

