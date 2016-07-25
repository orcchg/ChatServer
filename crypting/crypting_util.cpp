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

#include <sstream>
#include <vector>
#include "common.h"
#include "crypting_util.h"
#include "logger.h"

#include "crypting/aes_cryptor.h"
#include "crypting/cryptor.h"

namespace secure {

std::string encryptAndPack(const secure::Key& public_key, const std::string& plain, bool& encrypted) {
  TRC("encrypt(%zu)", public_key.getKey().length());
  encrypted = false;

  if (public_key != secure::Key::EMPTY) {
    secure::AESCryptor cryptor;  // generate symmetric key on-fly
    std::string cipher_hex = cryptor.encrypt(plain);
    size_t cipher_raw_length = cryptor.getRawLength();
    size_t cipher_hex_length = cipher_hex.length();
    TTY("Encrypted message[%zu]: %s", cipher_raw_length, cipher_hex.c_str());

    // encrypt E with public_key
    secure::SymmetricKey E = cryptor.getKeyCopy();
    size_t E_raw_length = E.getLength();
    // TODO: encrypt with pub key
    std::string E_hex = common::bin2hex(E.key, E_raw_length);
    size_t E_hex_length = E_hex.length();
    TTY("Encrypted symmetric key[%zu]: %s", E_raw_length, E_hex.c_str());

    // encrypt IV with public key
    unsigned char* IV = cryptor.getIVCopy();  // allocates memory
    size_t IV_raw_length = cryptor.getIVLength();
    // TODO: encrypt with pub key
    std::string IV_hex = common::bin2hex(IV, IV_raw_length);
    size_t IV_hex_length = IV_hex.length();
    TTY("Encrypted initial vector[%zu]: %s", IV_raw_length, IV_hex.c_str());

    // compound message with E
    // [hex size E:raw size E:hex size IV:raw IV size:size hash:hash:hex size msg:raw size msg]-----*****-----[ ..E.. ][ ..IV.. ][ ..msg.. ]
    // TODO: add hash
    std::string cipher_raw_length_str = std::to_string(cipher_raw_length);
    std::string cipher_hex_length_str = std::to_string(cipher_hex_length);
    std::string E_raw_length_str = std::to_string(E_raw_length);
    std::string E_hex_length_str = std::to_string(E_hex_length);
    std::string IV_raw_length_str = std::to_string(IV_raw_length);
    std::string IV_hex_length_str = std::to_string(IV_hex_length);

    std::ostringstream oss;
    oss << E_hex_length << COMPOUND_MESSAGE_DELIMITER << E_raw_length << COMPOUND_MESSAGE_DELIMITER
        << IV_hex_length << COMPOUND_MESSAGE_DELIMITER << IV_raw_length << COMPOUND_MESSAGE_DELIMITER
        << cipher_hex_length << COMPOUND_MESSAGE_DELIMITER << cipher_raw_length << COMPOUND_MESSAGE_SEPARATOR
        << E_hex << IV_hex << cipher_hex;
    std::string chunk = oss.str();
    TTY("Output buffer[%zu]: %s", chunk.length(), chunk.c_str());

    delete [] IV;  IV = nullptr;

    encrypted = true;
    return chunk;
  }
  return plain;  // not encrypted
}

std::string unpackAndDecrypt(const secure::Key& private_key, const std::string& chunk, bool& decrypted) {
  TRC("decrypt(%zu)", private_key.getKey().length());
  decrypted = false;

  if (private_key != secure::Key::EMPTY) {
    size_t ptr = 0;
    size_t i1 = chunk.find(COMPOUND_MESSAGE_SEPARATOR);
    size_t i2 = i1 + COMPOUND_MESSAGE_SEPARATOR_LENGTH;
    std::vector<std::string> values;
    common::split(chunk.substr(0, i1), COMPOUND_MESSAGE_DELIMITER, &values);
    int E_hex_length = std::stoi(values[0]);
    int E_raw_length = std::stoi(values[1]);
    int IV_hex_length = std::stoi(values[2]);
    int IV_raw_length = std::stoi(values[3]);
    int cipher_hex_length = std::stoi(values[4]);
    int cipher_raw_length = std::stoi(values[5]);
    // TODO: get hash
    TTY("Values: E length [%i:%i], IV [%i:%i], cipher length [%i:%i]",
        E_hex_length, E_raw_length, IV_hex_length, IV_raw_length, cipher_hex_length, cipher_raw_length);

    ptr = i2;              std::string cipher_hex_E = chunk.substr(ptr, E_hex_length);  // encrypted E
    ptr += E_hex_length;   std::string cipher_hex_IV = chunk.substr(ptr, IV_hex_length);  // encrypted IV
    ptr += IV_hex_length;  std::string cipher_hex_M = chunk.substr(ptr);  // encrypted message
    TTY("Cipher symmetric key: %s", cipher_hex_E.c_str());
    TTY("Cipher initial vector: %s", cipher_hex_IV.c_str());
    TTY("Cipher message: %s", cipher_hex_M.c_str());

    size_t o_E_raw_length = 0;
    unsigned char* cipher_raw_E = new unsigned char[E_raw_length];
    common::hex2bin(cipher_hex_E, cipher_raw_E, o_E_raw_length);
    if (o_E_raw_length != E_raw_length) {
      ERR("Encrypted E: raw length [%i] from bundle differs from actual length [%zu]", E_raw_length, o_E_raw_length);
    }

    // decrypt E with private key
    // TODO:
    secure::SymmetricKey E(cipher_raw_E);

    size_t o_IV_raw_length = 0;
    unsigned char* cipher_raw_IV = new unsigned char[IV_raw_length];
    common::hex2bin(cipher_hex_IV, cipher_raw_IV, o_IV_raw_length);
    if (o_IV_raw_length != IV_raw_length) {
      ERR("Encrypted IV: raw length [%i] from bundle differs from actual length [%zu]", IV_raw_length, o_IV_raw_length);
    }

    // TODO: decrypt IV with private key

    // decrypt message with E
    secure::AESCryptor cryptor(E, cipher_raw_IV);  // TODO: use decrypted IV
    std::string message = cryptor.decrypt(cipher_hex_M);
    TTY("Decrypted message[%zu]: %s", message.length(), message.c_str());

    delete [] cipher_raw_E;  cipher_raw_E = nullptr;
    delete [] cipher_raw_IV;  cipher_raw_IV = nullptr;

    decrypted = true;
    return message;
  }
  return chunk;  // not decrypted
}

}

#endif  // SECURE

