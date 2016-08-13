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

// ----------------------------------------------
#if SECURE
#include "icryptor.h"
#include "crypting/cryptor.h"
#include "crypting/crypting_util.h"

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
    ID_t id = document[ITEM_ID].GetInt64();
    std::string key = document[ITEM_KEY].GetString();
    return Key(id, key);
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
  : m_is_password_encrypted(false)
  , m_login(login)
  , m_password(password) {
}

std::string LoginForm::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_LOGIN "\":\"" << m_login
      << "\",\"" D_ITEM_PASSWORD "\":\"" << m_password
      << "\",\"" D_ITEM_ENCRYPTED "\":" << (m_is_password_encrypted ? 1 : 0)
      << "}";
  return oss.str();
}

LoginForm LoginForm::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString() &&
      document.HasMember(ITEM_ENCRYPTED) && document[ITEM_ENCRYPTED].IsInt()) {
    LoginForm form(document[ITEM_LOGIN].GetString(), document[ITEM_PASSWORD].GetString());
    form.setEncrypted(document[ITEM_ENCRYPTED].GetInt() != 0);
    return form;
  } else {
    ERR("Login Form parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

#if SECURE

// openssl encrypt with public key
void LoginForm::encrypt(const secure::Key& public_key) {
  m_password = secure::good::encryptRSA(public_key, m_password, m_is_password_encrypted);
  SYS("Encrypted password[%i]: %s", m_is_password_encrypted, m_password.c_str());
}

// openssl decrypt with private key
void LoginForm::decrypt(const secure::Key& private_key) {
  bool decrypted = false;
  m_password = secure::good::decryptRSA(private_key, m_password, decrypted);
  m_is_password_encrypted = !decrypted;
  SYS("Decrypted password[%i]: %s", m_is_password_encrypted, m_password.c_str());
}

#endif  // SECURE

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
      << "\",\"" D_ITEM_ENCRYPTED "\":" << (m_is_password_encrypted ? 1 : 0)
      << "}";
  return oss.str();
}

RegistrationForm RegistrationForm::fromJson(const std::string& json) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString() &&
      document.HasMember(ITEM_ENCRYPTED) && document[ITEM_ENCRYPTED].IsInt()) {
    RegistrationForm form(document[ITEM_LOGIN].GetString(), document[ITEM_EMAIL].GetString(), document[ITEM_PASSWORD].GetString());
    form.setEncrypted(document[ITEM_ENCRYPTED].GetInt() != 0);
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

Message::Message() {
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

Message::Message(const Message& message)
  : m_id(message.getId())
  , m_login(message.getLogin())
  , m_email(message.getEmail())
  , m_channel(message.getChannel())
  , m_dest_id(message.getDestId())
  , m_timestamp(message.getTimestamp())
  , m_size(message.getSize())
  , m_is_encrypted(message.isEncrypted())
  , m_message(message.getMessage()) {
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

bool Message::operator == (const Message& rhs) const {
  return m_id == rhs.m_id && m_dest_id == rhs.m_dest_id &&
    m_login == rhs.m_login && m_email == rhs.m_email &&
    m_channel == rhs.m_channel && m_timestamp == rhs.m_timestamp &&
    m_size == rhs.m_size && m_is_encrypted == rhs.m_is_encrypted &&
    m_message.compare(rhs.m_message) == 0;
}

bool Message::operator != (const Message& rhs) const {
  return !(*this == rhs);
}

#if SECURE

// openssl encrypt with public key
void Message::encrypt(secure::IAsymmetricCryptor& cryptor, const secure::Key& public_key) {
  m_message = secure::good::encryptAndPack(cryptor, public_key, m_message, m_is_encrypted);
  m_size = m_message.length();
  SYS("Encrypted message[%i]: %s", isEncrypted(), getMessage().c_str());
}

// openssl decrypt with private key
void Message::decrypt(secure::IAsymmetricCryptor& cryptor, const secure::Key& private_key) {
  bool decrypted = false;
  m_message = secure::good::unpackAndDecrypt(cryptor, private_key, m_message, decrypted);
  m_size = m_message.length();
  m_is_encrypted = !decrypted;
  SYS("Decrypted message[%i]: %s", isEncrypted(), getMessage().c_str());
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

