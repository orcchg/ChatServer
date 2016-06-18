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
#include "api/api.h"
#include "logger.h"
#include "request_prepare.h"

namespace util {

std::string getLoginForm_request(const std::string& host) {
  std::ostringstream oss;
  oss << "GET " D_PATH_LOGIN " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string getRegistrationForm_request(const std::string& host) {
  std::ostringstream oss;
  oss << "GET " D_PATH_REGISTER " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string sendLoginForm_request(const std::string& host, const LoginForm& form) {
  std::ostringstream oss;
  oss << "POST " D_PATH_LOGIN " HTTP/1.1\r\nHost: " << host << "\r\n\r\n"
      << "{\"" D_ITEM_LOGIN "\":\"" << form.getLogin()
      << "\",\"" D_ITEM_PASSWORD "\":\"" << form.getPassword() << "\"}";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string sendRegistrationForm_request(const std::string& host, const RegistrationForm& form) {
  std::ostringstream oss;
  oss << "POST " D_PATH_REGISTER " HTTP/1.1\r\nHost: " << host << "\r\n\r\n"
      << "{\"" D_ITEM_LOGIN "\":\"" << form.getLogin()
      << "\",\"" D_ITEM_EMAIL "\":\"" << form.getEmail()
      << "\",\"" D_ITEM_PASSWORD "\":\"" << form.getPassword() << "\"}";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string sendMessage_request(const std::string& host, const Message& message) {
  std::ostringstream oss;
  oss << "POST " D_PATH_MESSAGE " HTTP/1.1\r\nHost: " << host << "\r\n\r\n"
      << "{\"" D_ITEM_ID "\":" << message.getId()
      << ",\"" D_ITEM_LOGIN "\":\"" << message.getLogin()
      << "\",\"" D_ITEM_CHANNEL "\":" << message.getChannel()
      << ",\"" D_ITEM_DEST_ID "\":" << message.getDestId()
      << ",\"" D_ITEM_TIMESTAMP "\":" << message.getTimestamp()
      << ",\"" D_ITEM_MESSAGE "\":\"" << message.getMessage() << "\"}";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string logout_request(const std::string& host, ID_t id, const std::string& name) {
  std::ostringstream oss;
  oss << "DELETE " D_PATH_LOGOUT "?" D_ITEM_ID "=" << id
      << "&" D_ITEM_LOGIN "=" << name
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string switchChannel_request(const std::string& host, ID_t id, int channel, const std::string& name) {
  std::ostringstream oss;
  oss << "PUT " D_PATH_SWITCH_CHANNEL "?" D_ITEM_ID "=" << id
      << "&" D_ITEM_CHANNEL "=" << channel
      << "&" D_ITEM_LOGIN "=" << name
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string isLoggedIn_request(const std::string& host, const std::string& name) {
  std::ostringstream oss;
  oss << "GET " D_PATH_IS_LOGGED_IN "?" D_ITEM_LOGIN "=" << name
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string isRegistered_request(const std::string& host, const std::string& name) {
  std::ostringstream oss;
  oss << "GET " D_PATH_IS_REGISTERED "?" D_ITEM_LOGIN "=" << name
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

}

