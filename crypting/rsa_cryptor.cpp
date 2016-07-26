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
  init();
}

RSACryptor::~RSACryptor() {
}

std::string RSACryptor::encrypt(const std::string& source) {
  TRC("encrypt(%s)", source.c_str());
  FILE* public_key_file = fopen(m_public_key_filename.c_str(), "rt");
  if (public_key_file != nullptr) {
    BIO* bio = BIO_new_file(m_public_key_filename.c_str(), "r");
    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    //RSA* rsa = RSA_new();
    //rsa = PEM_read_RSA_PUBKEY(public_key_file, nullptr, nullptr, nullptr);
    fclose(public_key_file);
    if (rsa != nullptr) {
      auto size = source.length() * 2;  // large enough
      unsigned char* cipher = new unsigned char[size];
      int cipher_length = RSA_public_encrypt(source.length(), (unsigned char*) source.c_str(), cipher, rsa, RSA_PKCS1_PADDING);
      std::string encrypted = common::bin2hex(cipher, cipher_length);
      delete [] cipher;  cipher = nullptr;
      RSA_free(rsa);
      TTY("RSA encrypted: %s", encrypted.c_str());
      return encrypted;
    }
  } else {
    ERR("Unable to open file [%s] to get key", m_public_key_filename.c_str());
  }
  WRN("Public key wasn't provided, source hasn't been encrypted");
  return source;  // not encrypted
}

std::string RSACryptor::decrypt(const std::string& source) {
  TRC("decrypt(%s)", source.c_str());
  FILE* private_key_file = fopen(m_private_key_filename.c_str(), "rt");
  if (private_key_file != nullptr) {
    BIO* bio = BIO_new_file(m_private_key_filename.c_str(), "r");
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    //RSA* rsa = RSA_new();
    //rsa = PEM_read_RSAPrivateKey(private_key_file, nullptr, nullptr, nullptr);
    fclose(private_key_file);
    if (rsa != nullptr) {
      auto size = source.length() * 2;  // large enough
      size_t cipher_length = 0;
      unsigned char* plain = new unsigned char[size];
      unsigned char* cipher = new unsigned char[size];
      common::hex2bin(source, cipher, cipher_length);
      int plain_length = RSA_private_decrypt(cipher_length, cipher, plain, rsa, RSA_PKCS1_PADDING);
      std::string decrypted((const char*) plain);
      delete [] cipher;  cipher = nullptr;
      delete [] plain;   plain  = nullptr;
      RSA_free(rsa);
      TTY("RSA decrypted: %s", decrypted.c_str());
      return decrypted;
    }
  } else {
    ERR("Unable to open file [%s] to get key", m_private_key_filename.c_str());
  }
  WRN("Private key wasn't provided, source hasn't been decrypted");
  return source;  // not decrypted
}

/* Private */
// ----------------------------------------------------------------------------
bool RSACryptor::init() {
  return true;
}

}

#endif  // SECURE

