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
#include <openssl/conf.h>
#include <openssl/err.h>
#include "api/icryptor.h"
#include "aes_cryptor.h"
#include "common.h"
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

AESCryptor::AESCryptor(unsigned char* raw)
  : m_key(raw) {
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
  TRC("encrypt(%s)", source.c_str());
  auto size = source.length() * 2;  // large enough
  m_raw = new unsigned char[size];
  memset(m_raw, 0, size);

  unsigned char* key = (unsigned char*) "01234567890123456789012345678901";
  m_iv = "01234567890123456";

  int result = 1;
  int length = 0, cipher_length;
  result = EVP_EncryptInit_ex(m_context, EVP_aes_256_cbc(), nullptr, /*m_key.*/key, (unsigned char*) m_iv.c_str());
  if (result != 1) { goto E_ERROR; }
  result = EVP_EncryptUpdate(m_context, m_raw, &length, (unsigned char*) source.c_str(), source.length());
  if (result != 1) { goto E_ERROR; }
  cipher_length = length;
  result = EVP_EncryptFinal_ex(m_context, m_raw + length, &length);
  if (result != 1) { goto E_ERROR; }
  cipher_length += length;
  m_raw_length = cipher_length;
  return common::bin2hex(m_raw, cipher_length);

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
  TRC("decrypt(%s)", source.c_str());
  size_t size = source.length() * 2;  // large enough
  size_t cipher_length = 0;
  unsigned char plain[size], cipher[size];
  memset(plain, 0, size);
  common::hex2bin(source, cipher, cipher_length);

  unsigned char* key = (unsigned char*) "01234567890123456789012345678901";
  m_iv = "01234567890123456";

  int result = 1;
  int length = 0, plain_length;
  result = EVP_DecryptInit_ex(m_context, EVP_aes_256_cbc(), nullptr, /*m_key.*/key, (unsigned char*) m_iv.c_str());
  if (result != 1) { goto D_ERROR; }
  result = EVP_DecryptUpdate(m_context, plain, &length, (unsigned char*) cipher, cipher_length);
  if (result != 1) { goto D_ERROR; }
  plain_length = length;
  result = EVP_DecryptFinal_ex(m_context, plain + length, &length);
  if (result != 1) { goto D_ERROR; }
  plain_length += length;
  plain[plain_length] = '\0';
  return std::string((const char*) plain);

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
  m_raw = nullptr;
  m_raw_length = 0;

  m_iv = secure::random::generateString(SHA256_DIGEST_LENGTH >> 1);
  if (!(m_context = EVP_CIPHER_CTX_new())) {
    ERR("Failed to initialize context!");
    throw ConstructionException();
  }

  std::string key_hex = common::bin2hex(m_key.key, m_key.getLength());
  TTY("Key[%zu]: %s", m_key.getLength(), key_hex.c_str());
}

void AESCryptor::release() {
  EVP_CIPHER_CTX_free(m_context);
  EVP_cleanup();
  ERR_free_strings();
  delete [] m_raw;  m_raw = nullptr;
  m_raw_length = 0;
}

}

#endif  // SECURE

