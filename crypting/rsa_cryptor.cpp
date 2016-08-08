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
  : m_keypair(EVP_PKEY_new())
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

std::string RSACryptor::encrypt(const std::string& source, const Key& public_key) {
  TRC("encrypt(%s)", source.c_str());
  if (public_key != Key::EMPTY) {
    // load key
    DBG("%s", public_key.getKey().c_str());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, public_key.getKey().c_str(), public_key.getKey().length());
    PEM_read_bio_PUBKEY(bio, &m_keypair, nullptr, nullptr);
    PEM_write_PUBKEY(stdout, m_keypair);
    BIO_free(bio);

    // encrypt
    int pubkey_len = EVP_PKEY_size(m_keypair);
    unsigned char* cipher = new unsigned char[source.length() + EVP_MAX_IV_LENGTH];
    m_ek = new unsigned char[pubkey_len];
    m_iv = new unsigned char[EVP_MAX_IV_LENGTH];
    int block_len = 0;
    int cipher_len = 0;

    EVP_CIPHER_CTX* rsa_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_SealInit(rsa_enc_ctx, EVP_aes_256_cbc(), &m_ek, (int*) &m_ek_len, m_iv, &m_keypair, 1);
    EVP_SealUpdate(rsa_enc_ctx, cipher, (int*) &block_len, (unsigned char*) source.c_str(), source.length());
    cipher_len += block_len;
    EVP_SealFinal(rsa_enc_ctx, cipher + cipher_len, (int*) &block_len);
    cipher_len += block_len;
    EVP_CIPHER_CTX_free(rsa_enc_ctx);

    cipher[cipher_len] = '\0';
    std::string encrypted = std::string((const char*) cipher);
    delete [] cipher;  cipher = nullptr;
    return encrypted;
  }
  WRN("Public key wasn't provided, source hasn't been encrypted");
  return source;  // not encrypted
}

std::string RSACryptor::decrypt(const std::string& source, const Key& private_key) {
  TRC("decrypt(%s)", source.c_str());
  if (private_key != Key::EMPTY) {
    // load key
    DBG("%s", private_key.getKey().c_str());
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, private_key.getKey().c_str(), private_key.getKey().length());
    PEM_read_bio_PrivateKey(bio, &m_keypair, nullptr, nullptr);
    PEM_write_PrivateKey(stdout, m_keypair, nullptr, nullptr, 0, 0, nullptr);
    BIO_free(bio);

    // decrypt
    unsigned char* plain = new unsigned char[source.length() + m_iv_len];
    int block_len_x = 0;
    int plain_len = 0;

    EVP_CIPHER_CTX* rsa_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_OpenInit(rsa_dec_ctx, EVP_aes_256_cbc(), m_ek, m_ek_len, m_iv, m_keypair);
    EVP_OpenUpdate(rsa_dec_ctx, plain, (int*) &block_len_x, (unsigned char*) source.c_str(), source.length());
    plain_len += block_len_x;
    EVP_OpenFinal(rsa_dec_ctx, plain + plain_len, (int*) &block_len_x);
    plain_len += block_len_x;
    EVP_CIPHER_CTX_free(rsa_dec_ctx);

    plain[plain_len] = '\0';
    std::string message = std::string((const char*) plain);
    delete [] m_ek;   m_ek = nullptr;
    delete [] m_iv;   m_iv = nullptr;
    delete [] plain;  plain = nullptr;
    return message;
  }
  WRN("Private key wasn't provided, source hasn't been decrypted");
  return source;  // not decrypted
}

}

#endif  // SECURE

