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

#include <climits>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include "common.h"
#include "logger.h"
#include "random_util.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#define ERROR_BUFFER_SIZE 256
#define KEY_SIZE_BITS 2048
#define KEY_PUBLIC_EXPONENT 65537

namespace secure {
namespace random {

int setRandomSeed() {
  auto current = time(nullptr);
  srand(current % INT_MAX + 1);
}

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

std::string generateString(int length) {
  setRandomSeed();
  char* s = new char[length];
  for (int i = 0; i < length; ++i) {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }
  s[length] = 0;
  std::string result = std::string(s);
  delete [] s;
  return result;
}

// @see http://stackoverflow.com/questions/12647220/reading-and-writing-rsa-keys-to-a-pem-file-in-c

void generateKeyPair(ID_t id, const char* input, size_t size) {
  DBG("Generating key pair...  Input pattern: [%.*s]", (int) size, input);
  RAND_seed(input, size);

  RSA* rsa = nullptr;
  BIGNUM* exponent = BN_new();
  BIO* bp_public = nullptr;
  BIO* bp_private = nullptr;
  std::string public_key_filename, private_key_filename;

  int result = BN_set_word(exponent, RSA_F4);
  if (result != 1) { goto ERROR; }
  rsa = RSA_new();
  result = RSA_generate_key_ex(rsa, KEY_SIZE_BITS, exponent, nullptr);
  if (result != 1) { goto ERROR; }
  public_key_filename = common::createFilenameWithId(id, PUBLIC_KEY_FILE);
  bp_public = BIO_new_file(public_key_filename.c_str(), "w+");
  result = PEM_write_bio_RSAPublicKey(bp_public, rsa);
  if (result != 1) { goto ERROR; }
  private_key_filename = common::createFilenameWithId(id, PRIVATE_KEY_FILE);
  bp_private = BIO_new_file(private_key_filename.c_str(), "w+");
  result = PEM_write_bio_RSAPrivateKey(bp_private, rsa, nullptr, nullptr, 0, nullptr, nullptr);
  if (result != 1) { goto ERROR; }

  ERROR:
    if (result != 1) {
      char* error_buffer = new char[ERROR_BUFFER_SIZE];
      memset(error_buffer, 0, ERROR_BUFFER_SIZE);
      ERR_error_string_n(ERR_get_error(), error_buffer, ERROR_BUFFER_SIZE);
      ERR("Error during key generation: %s", error_buffer);
      delete [] error_buffer;  error_buffer = nullptr;
    }
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(rsa);
    BN_free(exponent);
}

std::pair<Key, Key> loadKeyPair(ID_t id, bool* accessible) {
  std::string public_key_str, private_key_str;
  std::string public_key_filename = common::createFilenameWithId(id, PUBLIC_KEY_FILE);
  std::string private_key_filename = common::createFilenameWithId(id, PRIVATE_KEY_FILE);

  if (common::isFileAccessible(public_key_filename)) {
    public_key_str = common::readFileToString(public_key_filename);
    // TRC("PUBLIC KEY: %s", public_key_str.c_str());
  } else {
    ERR("Public key file is not accessible: %s", public_key_filename.c_str());
    goto LOAD_KEY_ERROR;
  }
  if (common::isFileAccessible(private_key_filename)) {
    private_key_str = common::readFileToString(private_key_filename);
    // TRC("PRIVATE KEY: %s", private_key_str.c_str());
  } else {
    ERR("Private key file is not accessible: %s", private_key_filename.c_str());
    goto LOAD_KEY_ERROR;
  }

  {
    *accessible = true;
    Key public_key(id, public_key_str);
    Key private_key(id, private_key_str);
    return std::make_pair(public_key, private_key);
  }

  LOAD_KEY_ERROR:
    *accessible = false;
    return std::make_pair(Key::EMPTY, Key::EMPTY);
}

}
}

#endif  // SECURE

