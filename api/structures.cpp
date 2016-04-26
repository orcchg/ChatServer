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
#include "structures.h"

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
  oss << "{\"id\":" << m_id
      << ",\"login\":\"" << m_login
      << "\",\"channel\":" << m_channel
      << ",\"dest_id\":" << m_dest_id
      << ",\"timestamp\":" << m_timestamp
      << ",\"message\":\"" << m_message
      << "\"}";
  return oss.str();
}

