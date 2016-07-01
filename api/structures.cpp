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
#include "api.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "structures.h"
#if SECURE
#include "crypting/cryptor.h"
#include "icryptor.h"
#endif  // SECURE

// ----------------------------------------------
LoginForm::LoginForm(
    const std::string& login,
    const std::string& password)
  : m_login(login), m_password(password) {
}

// ----------------------------------------------
RegistrationForm::RegistrationForm(
    const std::string& login,
    const std::string& email,
    const std::string& password)
  : LoginForm(login, password), m_email(email) {
}

// ----------------------------------------------
Message::Builder::Builder(ID_t id)
  : m_id(id) {
}

Message::Builder& Message::Builder::setLogin(const std::string& login) {
  m_login = login;
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
  , m_channel(builder.getChannel())
  , m_dest_id(builder.getDestId())
  , m_timestamp(builder.getTimestamp())
  , m_message(builder.getMessage()) {
}

std::string Message::toJson() const {
  std::ostringstream oss;
  oss << "{\"" D_ITEM_ID "\":" << m_id
      << ",\"" D_ITEM_LOGIN "\":\"" << m_login
      << "\",\"" D_ITEM_CHANNEL "\":" << m_channel
      << ",\"" D_ITEM_DEST_ID "\":" << m_dest_id
      << ",\"" D_ITEM_TIMESTAMP "\":" << m_timestamp
      << ",\"" D_ITEM_MESSAGE "\":\"" << m_message
      << "\"}";
  return oss.str();
}

Message Message::fromJson(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt() &&
      document.HasMember(ITEM_DEST_ID) && document[ITEM_DEST_ID].IsInt64() &&
      document.HasMember(ITEM_TIMESTAMP) && document[ITEM_TIMESTAMP].IsInt64() &&
      document.HasMember(ITEM_MESSAGE) && document[ITEM_MESSAGE].IsString()) {
    ID_t id = document[ITEM_ID].GetInt64();
    std::string login = document[ITEM_LOGIN].GetString();
    int channel = document[ITEM_CHANNEL].GetInt();
    ID_t dest_id = document[ITEM_DEST_ID].GetInt64();
    uint64_t timestamp = document[ITEM_TIMESTAMP].GetInt64();
    std::string message = document[ITEM_MESSAGE].GetString();

    return Message::Builder(id).setLogin(login).setChannel(channel)
        .setDestId(dest_id).setTimestamp(timestamp).setMessage(message)
        .build();
  } else {
    ERR("Message parse failed: invalid json: %s", json.c_str());
    throw ConvertException();
  }
}

// ----------------------------------------------
Peer::Builder::Builder(ID_t id)
  : m_id(id) {
}

Peer::Builder& Peer::Builder::setLogin(const std::string& login) {
  m_login = login;
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
      << "\",\"" D_ITEM_CHANNEL "\":" << m_channel
      << "\"}";
  return oss.str();
}

Peer Peer::fromJson(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_CHANNEL) && document[ITEM_CHANNEL].IsInt()) {
    ID_t id = document[ITEM_ID].GetInt64();
    std::string login = document[ITEM_LOGIN].GetString();
    int channel = document[ITEM_CHANNEL].GetInt();

    return Peer::Builder(id).setLogin(login).setChannel(channel).build();
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

