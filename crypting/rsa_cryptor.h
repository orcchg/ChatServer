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

/**
 * @note:  cipher input string ('source') must be hex-encoded
 */
namespace secure {

class RSACryptorRaw {
public:
  RSACryptorRaw();
  virtual ~RSACryptorRaw();

  void setKeypair(const std::pair<Key, Key>& keypair);
  int encrypt(const std::string& source, unsigned char** cipher);
  int decrypt(unsigned char* cipher, int cipher_len, unsigned char** plain);

  inline int getEKlength() const { return m_ek_len; }
  inline int getIVlength() const { return m_iv_len; }
  void getEK(unsigned char* ek) const { memcpy(ek, m_ek, m_ek_len); }
  void getIV(unsigned char* iv) const { memcpy(iv, m_iv, m_iv_len); }

  void setEK(int ek_len, unsigned char* ek) {
    if (m_ek != nullptr) { delete [] m_ek;  m_ek = nullptr; }
    m_ek = new unsigned char[ek_len];
    m_ek_len = ek_len;
    memcpy(m_ek, ek, ek_len);
  }
  void setIV(int iv_len, unsigned char* iv) {
    if (m_iv != nullptr) { delete [] m_iv;  m_iv = nullptr; }
    m_iv = new unsigned char[iv_len];
    m_iv_len = iv_len;
    memcpy(m_iv, iv, iv_len);
  }

protected:
  RSA* m_rsa;
  EVP_PKEY* m_keypair;
  unsigned char* m_ek;
  unsigned char* m_iv;
  int m_ek_len;
  int m_iv_len;

  std::pair<Key, Key> m_keypair_pem;

  int doEncrypt(const std::string& source, unsigned char** cipher);
  int doDecrypt(unsigned char* cipher, int cipher_len, unsigned char** plain);
};

/* Wrapped */
// ----------------------------------------------------------------------------
class RSACryptorWrapped : public ICryptor {
public:
  RSACryptorWrapped();
  virtual ~RSACryptorWrapped();

  void setKeypair(const std::pair<Key, Key>& keypair);
  std::string encrypt(const std::string& source) override;
  std::string decrypt(const std::string& source) override;

private:
  int m_cipher_len;
  RSACryptorRaw m_cryptor;
};

// ----------------------------------------------
class RSACryptor : public IAsymmetricCryptor, private RSACryptorRaw {
public:
  RSACryptor();
  virtual ~RSACryptor();

  std::string encrypt(const std::string& source, const secure::Key& public_key, bool& encrypted) override;
  std::string decrypt(const std::string& source, const secure::Key& private_key, bool& decrypted) override;

  int getEKlength() const override { return RSACryptorRaw::getEKlength(); }
  int getIVlength() const override { return RSACryptorRaw::getIVlength(); }
  inline int getCipherLength() const override { return m_cipher_len; }
  void getEK(unsigned char* ek) const override { RSACryptorRaw::getEK(ek); }
  void getIV(unsigned char* iv) const override { RSACryptorRaw::getIV(iv); }

  inline void setCipherLength(int cipher_len) override { m_cipher_len = cipher_len; }
  void setEK(int ek_len, unsigned char* ek) override { RSACryptorRaw::setEK(ek_len, ek); }
  void setIV(int iv_len, unsigned char* iv) override { RSACryptorRaw::setIV(iv_len, iv); }

private:
  int m_cipher_len;
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_RSA_CRYPTOR__H__

