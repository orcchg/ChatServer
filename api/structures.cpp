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

#include <sstream>
#include <cstdlib>
#include <cstring>
#include "api.h"
#include "common.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "structures.h"

#if SECURE
#include "crypting/aes_cryptor.h"
#include "crypting/cryptor.h"
#include "icryptor.h"
#endif  // SECURE

// ----------------------------------------------
#if SECURE

namespace secure {

Key Key::EMPTY;

Key::Key()
  : m_id(UNKNOWN_ID), m_key("") {
}

Key::Key(ID_t id, const std::string& key)
  : m_id(id), m_key(key) {
}

bool Key::operator == (const Key& rhs) const {
  return (m_id == rhs.m_id && m_key == rhs.m_key);
}

bool Key::operator != (const Key& rhs) const {
  return !(*this == rhs);
}

std::string Key::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_ID "\":" << m_id
      << ",\"" D_ITEM_KEY "\":\"" << m_key
      << "\"}";
  return oss.str();
}

Key Key::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_KEY) && document[ITEM_KEY].IsString()) {
    return Key(document[ITEM_ID].GetInt64(), document[ITEM_KEY].GetString());
  } else {
    ERR("Key parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

}

#endif  // SECURE

// ----------------------------------------------
LoginForm::LoginForm(
    const std::string& login,
    const std::string& password)
  : m_login(login), m_password(password) {
}

std::string LoginForm::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_LOGIN "\":\"" << m_login
      << "\",\"" D_ITEM_PASSWORD "\":\"" << m_password
      << "\"}";
  return oss.str();
}

LoginForm LoginForm::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    LoginForm form(document[ITEM_LOGIN].GetString(), document[ITEM_PASSWORD].GetString());
    return form;
  } else {
    ERR("Login Form parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

// ----------------------------------------------
RegistrationForm::RegistrationForm(
    const std::string& login,
    const std::string& email,
    const std::string& password)
  : LoginForm(login, password), m_email(email) {
}

std::string RegistrationForm::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_LOGIN "\":\"" << m_login
      << "\",\"" D_ITEM_EMAIL "\":\"" << m_email
      << "\",\"" D_ITEM_PASSWORD "\":\"" << m_password
      << "\"}";
  return oss.str();
}

RegistrationForm RegistrationForm::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    RegistrationForm form(document[ITEM_LOGIN].GetString(), document[ITEM_EMAIL].GetString(), document[ITEM_PASSWORD].GetString());
    return form;
  } else {
    ERR("Registration Form parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

// ----------------------------------------------
Message::Builder::Builder(ID_t id)
  : m_id(id) {
}

Message::Builder& Message::Builder::setLogin(const std::string& login) {
  m_login = login;
  return *this;
}

Message::Builder& Message::Builder::setEmail(const std::string& email) {
  m_email = email;
  return *this;
}

Message::Builder& Message::Builder::setChannel(int channel) {
  m_channel = channel;
  return *this;
}

Message::Builder& Message::Builder::setDestId(ID_t dest_id) {
  m_dest_id = dest_id;
  return *this;
}

Message::Builder& Message::Builder::setTimestamp(uint64_t timestamp) {
  m_timestamp = timestamp;
  return *this;
}

Message::Builder& Message::Builder::setSize(size_t size) {
  m_size = size;
  return *this;
}

Message::Builder& Message::Builder::setEncrypted(bool is_encrypted) {
  m_is_encrypted = is_encrypted;
  return *this;
}

Message::Builder& Message::Builder::setMessage(const std::string& message) {
  m_message = message;
  return *this;
}

Message Message::Builder::build() {
  return Message(*this);
}

Message::Message(const Message::Builder& builder)
  : m_id(builder.getId())
  , m_login(builder.getLogin())
  , m_email(builder.getEmail())
  , m_channel(builder.getChannel())
  , m_dest_id(builder.getDestId())
  , m_timestamp(builder.getTimestamp())
  , m_size(builder.getSize())
  , m_is_encrypted(builder.isEncrypted())
  , m_message(builder.getMessage()) {
}

std::string Message::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_ID "\":" << m_id
      << ",\"" D_ITEM_LOGIN "\":\"" << m_login
      << "\",\"" D_ITEM_EMAIL "\":\"" << m_email
      << "\",\"" D_ITEM_CHANNEL "\":" << m_channel
      << ",\"" D_ITEM_DEST_ID "\":" << m_dest_id
      << ",\"" D_ITEM_TIMESTAMP "\":" << m_timestamp
      << ",\"" D_ITEM_SIZE "\":" << m_message.size()
      << ",\"" D_ITEM_ENCRYPTED "\":" << (m_is_encrypted ? 1 : 0)
      << ",\"" D_ITEM_MESSAGE "\":\"" << m_message
      << "\"}";
  return oss.str();
}

Message Message::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt() &&
      document.HasMember(ITEM_DEST_ID) && document[ITEM_DEST_ID].IsInt64() &&
      document.HasMember(ITEM_TIMESTAMP) && document[ITEM_TIMESTAMP].IsInt64() &&
      document.HasMember(ITEM_SIZE) && document[ITEM_SIZE].IsInt() &&
      document.HasMember(ITEM_ENCRYPTED) && document[ITEM_ENCRYPTED].IsInt() &&
      document.HasMember(ITEM_MESSAGE) && document[ITEM_MESSAGE].IsString()) {
    ID_t id = document[ITEM_ID].GetInt64();
    std::string login = document[ITEM_LOGIN].GetString();
    std::string email = document[ITEM_EMAIL].GetString();
    int channel = document[ITEM_CHANNEL].GetInt();
    ID_t dest_id = document[ITEM_DEST_ID].GetInt64();
    uint64_t timestamp = document[ITEM_TIMESTAMP].GetInt64();
    size_t size = document[ITEM_SIZE].GetInt();
    bool is_encrypted = document[ITEM_ENCRYPTED].GetInt() != 0;
    std::string message = document[ITEM_MESSAGE].GetString();

    return Message::Builder(id).setLogin(login).setEmail(email).setChannel(channel)
        .setDestId(dest_id).setTimestamp(timestamp).setSize(size)
        .setEncrypted(is_encrypted).setMessage(message)
        .build();
  } else {
    ERR("Message parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

#if SECURE

// @see http://www.czeskis.com/random/openssl-encrypt-file.html
// @see https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

// openssl encrypt with public key
void Message::encrypt(const secure::Key& public_key) {
  TRC("encrypt(%s)", public_key.getKey().c_str());
  if (public_key != secure::Key::EMPTY) {
    secure::AESCryptor cryptor;  // generate symmetric key on-fly
    std::string cipher = cryptor.encrypt(m_message);
    size_t cipher_raw_length = cryptor.getRawLength();
    size_t cipher_hex_length = cipher.length();
    TTY("Encrypted message[%zu]: %s", cipher_raw_length, cipher.c_str());

    // encrypt E with public_key
    secure::SymmetricKey E = cryptor.getKeyCopy();
    // TODO: encrypt with pub key
    size_t E_raw_length = E.getLength();
    std::string E_hex = common::bin2hex(E.key, E_raw_length);
    size_t E_hex_length = E_hex.length();
    TTY("Encrypted symmetric key[%zu]: %s", E_raw_length, E_hex.c_str());

    // compound message with E
    // [hex size E:raw size E:size hash:hash:hex size msg:raw size msg]-----*****-----[ ..E.. ][ ..msg.. ]
    // TODO: add hash
    std::string cipher_raw_length_str = std::to_string(cipher_raw_length);
    std::string cipher_hex_length_str = std::to_string(cipher_hex_length);
    std::string E_raw_length_str = std::to_string(E_raw_length);
    std::string E_hex_length_str = std::to_string(E_hex_length);

    std::ostringstream oss;
    oss << E_hex_length << COMPOUND_MESSAGE_DELIMITER << E_raw_length << COMPOUND_MESSAGE_DELIMITER
        << cipher_hex_length << COMPOUND_MESSAGE_DELIMITER << cipher_raw_length << COMPOUND_MESSAGE_SEPARATOR
        << E_hex << cipher;
    m_message = oss.str();
    TTY("Output buffer[%zu]: %s", m_message.length(), m_message.c_str());

    m_is_encrypted = true;  // set encrypted
  }
}

// openssl decrypt with private key
void Message::decrypt(const secure::Key& private_key) {
  TRC("decrypt(%s)", private_key.getKey().c_str());
  if (private_key != secure::Key::EMPTY) {
    size_t ptr = 0;
    size_t i1 = m_message.find(COMPOUND_MESSAGE_SEPARATOR);
    size_t i2 = i1 + COMPOUND_MESSAGE_SEPARATOR_LENGTH;
    std::vector<std::string> values;
    common::split(m_message.substr(0, i1), COMPOUND_MESSAGE_DELIMITER, &values);
    int E_hex_length = std::stoi(values[0]);
    int E_raw_length = std::stoi(values[1]);
    int cipher_hex_length = std::stoi(values[2]);
    int cipher_raw_length = std::stoi(values[3]);
    // TODO: get hash
    TTY("Values: E length [%i:%i], cipher length [%i:%i]", E_hex_length, E_raw_length, cipher_hex_length, cipher_raw_length);

    std::string cipher_hex_E = m_message.substr(i2, E_hex_length);  // encrypted E
    std::string cipher_hex_M = m_message.substr(i2 + E_hex_length);  // encrypted message
    TTY("Encrypted E: %s", cipher_hex_E.c_str());
    TTY("Cipher %s", cipher_hex_M.c_str());

    size_t o_E_raw_length = 0;
    unsigned char* cipher_raw_E = new unsigned char[E_raw_length];
    //unsigned char* cipher_raw_M = new unsigned char[cipher_raw_length];
    //TODO: common::hex2bin(cipher_hex_E, cipher_raw_E, o_E_raw_length);
    //common::hex2bin(cipher_hex_M, cipher_raw_M, cipher_raw_length);
    if (o_E_raw_length != E_raw_length) {
      ERR("Encrypted E: raw length [%i] from bundle differs from actual length [%zu]", E_raw_length, o_E_raw_length);
    }

    // decrypt E with private key
    // TODO:
    secure::SymmetricKey E(cipher_raw_E);

    // decrypt message with E
    secure::AESCryptor cryptor(E);
    m_message = cryptor.decrypt(cipher_hex_M);
    TTY("Decrypted message[%zu]: %s", m_message.length(), m_message.c_str());

    delete [] cipher_raw_E;  cipher_raw_E = nullptr;
    //delete [] cipher_raw_M;  cipher_raw_M = nullptr;

    m_is_encrypted = false;  // set decrypted
  }
}

#endif  // SECURE

// ----------------------------------------------
Peer::Builder::Builder(ID_t id)
  : m_id(id) {
}

Peer::Builder& Peer::Builder::setLogin(const std::string& login) {
  m_login = login;
  return *this;
}

Peer::Builder& Peer::Builder::setEmail(const std::string& email) {
  m_email = email;
  return *this;
}

Peer::Builder& Peer::Builder::setChannel(int channel) {
  m_channel = channel;
  return *this;
}

Peer Peer::Builder::build() {
  return Peer(*this);
}

Peer::Peer(const Peer::Builder& builder)
  : m_id(builder.getId())
  , m_login(builder.getLogin())
  , m_channel(builder.getChannel()) {
}

std::string Peer::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_ID "\":" << m_id
      << ",\"" D_ITEM_LOGIN "\":\"" << m_login
      << "\",\"" D_ITEM_EMAIL "\":\"" << m_email
      << "\",\"" D_ITEM_CHANNEL "\":" << m_channel
      << "\"}";
  return oss.str();
}

Peer Peer::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt()) {
    ID_t id = document[ITEM_ID].GetInt64();
    std::string login = document[ITEM_LOGIN].GetString();
    std::string email = document[ITEM_EMAIL].GetString();
    int channel = document[ITEM_CHANNEL].GetInt();

    return Peer::Builder(id).setLogin(login).setEmail(email).setChannel(channel).build();
  } else {
    ERR("Peer parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

// ----------------------------------------------
Token Token::EMPTY = Token("");

Token::Token(const std::string& input) {
#if SECURE
  secure::ICryptor* cryptor = new secure::Cryptor();
  m_token = cryptor->encrypt(input);
  delete cryptor;  cryptor = nullptr;
#else
  m_token = input;
#endif  // SECURE
}

Token::Token(const Token& token)
  : m_token(token.m_token) {
}

Token::~Token() {
}

const std::string& Token::get() const {
  return m_token;
}

std::ostream& operator << (std::ostream& out, const Token& token) {
  out << token.get();
  return out;
}

