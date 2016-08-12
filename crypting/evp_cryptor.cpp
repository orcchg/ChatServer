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

#include "common.h"
#include "evp_cryptor.h"
#include "logger.h"

namespace secure {

/* Core utils */
// ----------------------------------------------
void handleErrors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int envelopeSeal(
    EVP_PKEY** pub_key,
    unsigned char* plaintext, int plaintext_len,
    unsigned char** encrypted_key, int* encrypted_key_len,
    unsigned char* iv,
    unsigned char* ciphertext) {

  EVP_CIPHER_CTX* ctx;
  int ciphertext_len = 0;
  int len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR("Create context for seal");
    handleErrors();
  }

  /* Initialise the envelope seal operation. This operation generates
   * a key for the provided cipher, and then encrypts that key a number
   * of times (one for each public key provided in the pub_key array). In
   * this example the array size is just one. This operation also
   * generates an IV and places it in iv. */
  if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, 1)) {
    ERR("Seal init");
    handleErrors();
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_SealUpdate can be called multiple times if necessary
   */
  if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    ERR("Seal update");
    handleErrors();
  }

  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) {
    ERR("Seal final");
    handleErrors();
  }

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int envelopeOpen(
    EVP_PKEY* priv_key,
    unsigned char* ciphertext, int ciphertext_len,
    unsigned char* encrypted_key, int encrypted_key_len,
    unsigned char* iv,
    unsigned char* plaintext) {

  EVP_CIPHER_CTX* ctx;
  int len = 0;
  int plaintext_len = 0;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    ERR("Create context for open");
    handleErrors();
  }

  /* Initialise the decryption operation. The asymmetric private key is
   * provided and priv_key, whilst the encrypted session key is held in
   * encrypted_key */
  if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, priv_key)) {
    ERR("Open init");
    handleErrors();
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_OpenUpdate can be called multiple times if necessary
   */
  if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    ERR("Open update");
    handleErrors();
  }

  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) {
    ERR("Open final");
    handleErrors();
  }

  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/* Cryptor */
// ----------------------------------------------------------------------------
EVPCryptor::EVPCryptor()
  : m_ek_len(0)
  , m_iv_len(EVP_MAX_IV_LENGTH)
  , m_cipher_len(0)
  , m_ek(nullptr)
  , m_iv(nullptr) {
}

EVPCryptor::~EVPCryptor() {
  delete [] m_ek;  m_ek = nullptr;
  delete [] m_iv;  m_iv = nullptr;
}

std::string EVPCryptor::encrypt(const std::string& source, const secure::Key& public_pem, bool& encrypted) {
  encrypted = false;
  if (public_pem != Key::EMPTY) {
    BIO* public_bio = BIO_new(BIO_s_mem());
    BIO_write(public_bio, public_pem.getKey().c_str(), public_pem.getKey().length());
    RSA* public_rsa = RSA_new();
    EVP_PKEY* public_key = EVP_PKEY_new();
    PEM_read_bio_RSAPublicKey(public_bio, &public_rsa, nullptr, nullptr);
    EVP_PKEY_assign_RSA(public_key, public_rsa);
    BIO_free(public_bio);

    int pubkey_len = EVP_PKEY_size(public_key);
    m_ek = new unsigned char[pubkey_len];
    m_iv = new unsigned char[EVP_MAX_IV_LENGTH];
    unsigned char* cipher = new unsigned char[source.length() + EVP_MAX_IV_LENGTH];

    m_cipher_len = envelopeSeal(&public_key, (unsigned char*) source.c_str(), source.length(), &m_ek, &m_ek_len, m_iv, cipher);
    EVP_PKEY_free(public_key);

    encrypted = true;
    std::string message = common::bin2hex(cipher, m_cipher_len);
    delete [] cipher;  cipher = nullptr;
    return message;
  }
  WRN("Public key wasn't provided, source hasn't been encrypted");
  return source;
}

std::string EVPCryptor::decrypt(const std::string& source, const secure::Key& private_pem, bool& decrypted) {
  decrypted = false;
  if (private_pem != Key::EMPTY) {
    BIO* private_bio = BIO_new(BIO_s_mem());
    BIO_write(private_bio, private_pem.getKey().c_str(), private_pem.getKey().length());
    RSA* private_rsa = RSA_new();
    EVP_PKEY* private_key = EVP_PKEY_new();
    PEM_read_bio_RSAPrivateKey(private_bio, &private_rsa, nullptr, nullptr);
    EVP_PKEY_assign_RSA(private_key, private_rsa);
    BIO_free(private_bio);

    size_t o_cipher_len = 0;
    unsigned char* cipher = new unsigned char[m_cipher_len];
    unsigned char* plain = new unsigned char[m_cipher_len + m_iv_len];
    common::hex2bin(source, cipher, o_cipher_len);

    int plain_len = envelopeOpen(private_key, cipher, m_cipher_len, m_ek, m_ek_len, m_iv, plain);
    plain[plain_len] = '\0';
    EVP_PKEY_free(private_key);

    decrypted = true;
    std::string message((const char*) plain);
    delete [] cipher;  cipher = nullptr;
    delete [] plain;  plain = nullptr;
    return message;
  }
  WRN("Private key wasn't provided, source hasn't been decrypted");
  return source;
}

}

#endif  // SECURE
