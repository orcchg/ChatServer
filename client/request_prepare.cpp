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
 *
 *   This program and text files composing it, and/or compiled binary files
 *   (object files, shared objects, binary executables) obtained from text
 *   files of this program using compiler, as well as other files (text, images, etc.)
 *   composing this program as a software project, or any part of it,
 *   cannot be used by 3rd-parties in any commercial way (selling for money or for free,
 *   advertising, commercial distribution, promotion, marketing, publishing in media, etc.).
 *   Only the original author - Maxim Alov - has right to do any of the above actions.
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
      << form.toJson();
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string sendRegistrationForm_request(const std::string& host, const RegistrationForm& form) {
  std::ostringstream oss;
  oss << "POST " D_PATH_REGISTER " HTTP/1.1\r\nHost: " << host << "\r\n\r\n"
      << form.toJson();
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string sendMessage_request(const std::string& host, const Message& message) {
  std::ostringstream oss;
  oss << "POST " D_PATH_MESSAGE " HTTP/1.1\r\nHost: " << host << "\r\n\r\n"
      << message.toJson();
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string logout_request(const std::string& host, ID_t id) {
  std::ostringstream oss;
  oss << "DELETE " D_PATH_LOGOUT "?" D_ITEM_ID "=" << id
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string switchChannel_request(const std::string& host, ID_t id, int channel) {
  std::ostringstream oss;
  oss << "PUT " D_PATH_SWITCH_CHANNEL "?" D_ITEM_ID "=" << id
      << "&" D_ITEM_CHANNEL "=" << channel
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

std::string getAllPeers_request(const std::string& host) {
  std::ostringstream oss;
  oss << "GET " D_PATH_ALL_PEERS << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string getAllPeers_request(const std::string& host, int channel) {
  std::ostringstream oss;
  oss << "GET " D_PATH_ALL_PEERS "?" D_ITEM_CHANNEL "=" << channel
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

/* Private secure communication */
// ----------------------------------------------------------------------------
#if SECURE

std::string privateRequest_request(const std::string& host, int src_id, int dest_id) {
  std::ostringstream oss;
  oss << "POST " D_PATH_PRIVATE_REQUEST "?" D_ITEM_SRC_ID "=" << src_id
      << "&" D_ITEM_DEST_ID "=" << dest_id
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string privateConfirm_request(const std::string& host, int src_id, int dest_id, bool accept) {
  std::ostringstream oss;
  oss << "POST " D_PATH_PRIVATE_CONFIRM "?" D_ITEM_SRC_ID "=" << src_id
      << "&" D_ITEM_DEST_ID "=" << dest_id
      << "&" D_ITEM_ACCEPT "=" << (accept ? 1 : 0)
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string privateAbort_request(const std::string& host, int src_id, int dest_id) {
  std::ostringstream oss;
  oss << "DELETE " D_PATH_PRIVATE_ABORT "?" D_ITEM_SRC_ID "=" << src_id
      << "&" D_ITEM_DEST_ID "=" << dest_id
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string privatePubKey_request(const std::string& host, int src_id, const secure::Key& key) {
  std::ostringstream oss;
  oss << "POST " D_PATH_PRIVATE_PUBKEY "?" D_ITEM_ID "=" << src_id
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n"
      << "{\"" D_ITEM_PRIVATE_PUBKEY "\":" << key.toJson() << "}";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

std::string privatePubKeysExchange_request(const std::string& host, int src_id, int dest_id) {
  std::ostringstream oss;
  oss << "POST " D_PATH_PRIVATE_PUBKEY_EXCHANGE "?" D_ITEM_SRC_ID "=" << src_id
      << "&" D_ITEM_DEST_ID "=" << dest_id
      << " HTTP/1.1\r\nHost: " << host << "\r\n\r\n";
  MSG("Request: %s", oss.str().c_str());
  return oss.str();
}

#endif  // SECURE

}

