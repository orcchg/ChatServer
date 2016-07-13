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
#include <openssl/conf.h>
#include <openssl/err.h>
#include "api/icryptor.h"
#include "aes_cryptor.h"
#include "logger.h"
#include "random_util.h"

#define ERROR_BUFFER_SIZE 256

// @see http://www.czeskis.com/random/openssl-encrypt-file.html
// @see https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

namespace secure {

AESCryptor::AESCryptor()
  : m_key() {
  init();
}

AESCryptor::AESCryptor(const SymmetricKey& key)
  : m_key(key) {
  init();
}

AESCryptor::~AESCryptor() {
  release();
}

std::string AESCryptor::encrypt(const std::string& source) {
  auto size = source.length() * 2;  // large enough
  unsigned char cipher[size];
  memset(cipher, 0, size);

  int result = 1;
  int length = 0, cipher_length;
  result = EVP_EncryptInit_ex(m_context, EVP_aes_256_cbc(), nullptr, m_key.key, (const unsigned char*) m_iv.c_str());
  if (result != 1) { goto E_ERROR; }
  result = EVP_EncryptUpdate(m_context, cipher, &length, (const unsigned char*) source.c_str(), source.length());
  if (result != 1) { goto E_ERROR; }
  cipher_length = length;
  result = EVP_EncryptFinal_ex(m_context, cipher + length, &length);
  if (result != 1) { goto E_ERROR; }
  cipher_length += length;
  return std::string((char*) cipher);

  E_ERROR:
    if (result != 1) {
      char* error_buffer = new char[ERROR_BUFFER_SIZE];
      memset(error_buffer, 0, ERROR_BUFFER_SIZE);
      ERR_error_string_n(ERR_get_error(), error_buffer, ERROR_BUFFER_SIZE);
      ERR("Error during AES encryption: %s", error_buffer);
      delete [] error_buffer;  error_buffer = nullptr;
    }

  return source;
}

std::string AESCryptor::decrypt(const std::string& source) {
  auto size = source.length();
  unsigned char plain[size];
  memset(plain, 0, size);

  int result = 1;
  int length = 0, plain_length;
  result = EVP_DecryptInit_ex(m_context, EVP_aes_256_cbc(), nullptr, m_key.key, (const unsigned char*) m_iv.c_str());
  if (result != 1) { goto D_ERROR; }
  result = EVP_DecryptUpdate(m_context, plain, &length, (const unsigned char*) source.c_str(), source.length());
  if (result != 1) { goto D_ERROR; }
  plain_length = length;
  result = EVP_DecryptFinal_ex(m_context, plain + length, &length);
  if (result != 1) { goto D_ERROR; }
  plain_length += length;
  return std::string((char*) plain);

  D_ERROR:
    if (result != 1) {
      char* error_buffer = new char[ERROR_BUFFER_SIZE];
      memset(error_buffer, 0, ERROR_BUFFER_SIZE);
      ERR_error_string_n(ERR_get_error(), error_buffer, ERROR_BUFFER_SIZE);
      ERR("Error during AES decryption: %s", error_buffer);
      delete [] error_buffer;  error_buffer = nullptr;
    }

  return source;
}

/* Private */
// ----------------------------------------------------------------------------
void AESCryptor::init() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(nullptr);

  m_iv = secure::random::generateString(SHA256_DIGEST_LENGTH >> 1);
  if (!(m_context = EVP_CIPHER_CTX_new())) {
    ERR("Failed to initialize context!");
    throw ConstructionException();
  }
}

void AESCryptor::release() {
  EVP_CIPHER_CTX_free(m_context);
  EVP_cleanup();
  ERR_free_strings();
}

}

#endif  // SECURE

