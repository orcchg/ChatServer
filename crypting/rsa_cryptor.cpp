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

RSACryptor::RSACryptor()
  : m_rsa(RSA_new())
  , m_keypair(EVP_PKEY_new())
  , m_ek(nullptr)
  , m_iv(nullptr)
  , m_ek_len(0)
  , m_iv_len(EVP_MAX_IV_LENGTH) {
}

RSACryptor::~RSACryptor() {
  EVP_PKEY_free(m_keypair);  m_keypair = nullptr;
  delete [] m_ek;  m_ek = nullptr;
  delete [] m_iv;  m_iv = nullptr;
}

// @see http://stackoverflow.com/questions/17400058/how-to-use-openssl-lib-pem-read-to-read-public-private-key-from-a-string

void RSACryptor::setKeypair(const std::pair<Key, Key>& keypair) {
  m_keypair_pem = keypair;

  {
    const auto& public_key = m_keypair_pem.first;
    DBG("%s", public_key.getKey().c_str());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, public_key.getKey().c_str(), public_key.getKey().length());
    PEM_read_bio_RSAPublicKey(bio, &m_rsa, nullptr, nullptr);
    BIO_free(bio);
  }

  {
    const auto& private_key = m_keypair_pem.second;
    DBG("%s", private_key.getKey().c_str());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, private_key.getKey().c_str(), private_key.getKey().length());
    PEM_read_bio_RSAPrivateKey(bio, &m_rsa, nullptr, nullptr);
    BIO_free(bio);
  }

  EVP_PKEY_assign_RSA(m_keypair, m_rsa);
  int pubkey_len = EVP_PKEY_size(m_keypair);
  m_ek = new unsigned char[pubkey_len];
  m_iv = new unsigned char[EVP_MAX_IV_LENGTH];
}

int RSACryptor::encrypt(const std::string& source, unsigned char** cipher) {
  TRC("encrypt(%s)", source.c_str());
  const auto& public_key = m_keypair_pem.first;
  if (public_key != Key::EMPTY) {
    int block_len = 0;
    int cipher_len = 0;

    EVP_CIPHER_CTX* rsa_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_SealInit(rsa_enc_ctx, EVP_aes_256_cbc(), &m_ek, &m_ek_len, m_iv, &m_keypair, 1);
    EVP_SealUpdate(rsa_enc_ctx, *cipher, &block_len, (unsigned char*) source.c_str(), source.length());
    cipher_len += block_len;
    EVP_SealFinal(rsa_enc_ctx, *cipher + cipher_len, &block_len);
    cipher_len += block_len;
    EVP_CIPHER_CTX_free(rsa_enc_ctx);
    INF("RSA Cipher length: %i", cipher_len);
    TTY("RSA Cipher[%i]: %.*s", cipher_len, cipher_len, *cipher);
    return cipher_len;
  }
  WRN("Public key wasn't provided, source hasn't been encrypted");
  return 0;  // not encrypted
}

int RSACryptor::decrypt(unsigned char* cipher, int cipher_len, unsigned char** plain) {
  TRC("decrypt(%i)", cipher_len);
  const auto& private_key = m_keypair_pem.second;
  if (private_key != Key::EMPTY) {
    int block_len = 0;
    int plain_len = 0;

    EVP_CIPHER_CTX* rsa_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_OpenInit(rsa_dec_ctx, EVP_aes_256_cbc(), m_ek, m_ek_len, m_iv, m_keypair);
    EVP_OpenUpdate(rsa_dec_ctx, *plain, &block_len, cipher, cipher_len);
    plain_len += block_len;
    EVP_OpenFinal(rsa_dec_ctx, *plain + plain_len, &block_len);
    plain_len += block_len;
    EVP_CIPHER_CTX_free(rsa_dec_ctx);
    INF("RSA Plain length: %i", plain_len);
    TTY("RSA Plain[%i]: %.*s", plain_len, plain_len, *plain);
    (*plain)[plain_len] = '\0';
    return plain_len;
  }
  WRN("Private key wasn't provided, source hasn't been decrypted");
  return 0;  // not decrypted
}

/* Wrapped */
// ----------------------------------------------------------------------------
RSACryptorWrapped::RSACryptorWrapped()
  : m_cipher_len(0) {
}

RSACryptorWrapped::~RSACryptorWrapped() {
}

void RSACryptorWrapped::setKeypair(const std::pair<Key, Key>& keypair) {
  m_cryptor.setKeypair(keypair);
}

std::string RSACryptorWrapped::encrypt(const std::string& source) {
  unsigned char* cipher = new unsigned char[source.length() + EVP_MAX_IV_LENGTH];
  m_cipher_len = m_cryptor.encrypt(source, &cipher);
  if (m_cipher_len > 0) {
    std::string result = common::bin2hex(cipher, m_cipher_len);
    delete [] cipher;  cipher = nullptr;
    return result;
  }
  delete [] cipher;  cipher = nullptr;
  return source;
}

std::string RSACryptorWrapped::decrypt(const std::string& source) {
  unsigned char* cipher = new unsigned char[m_cipher_len];
  size_t cipher_len = 0;
  common::hex2bin(source, cipher, cipher_len);
  unsigned char* plain = new unsigned char[m_cipher_len + EVP_MAX_IV_LENGTH];
  int plain_len = m_cryptor.decrypt(cipher, m_cipher_len, &plain);
  if (plain_len > 0) {
    std::string result = std::string((const char*) plain);
    delete [] cipher;  cipher = nullptr;
    delete [] plain;   plain  = nullptr;
    return result;
  }
  delete [] cipher;  cipher = nullptr;
  delete [] plain;   plain  = nullptr;
  return source;
}

}

#endif  // SECURE

