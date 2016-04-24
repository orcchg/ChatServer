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
#include "all.h"
#include "api.h"
#include "server_api_impl.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#define D_ITEM_LOGIN "login"
#define D_ITEM_EMAIL "email"
#define D_ITEM_PASSWORD "password"

const char* ITEM_LOGIN = D_ITEM_LOGIN;
const char* ITEM_EMAIL = D_ITEM_EMAIL;
const char* ITEM_PASSWORD = D_ITEM_PASSWORD;

ServerApiImpl::ServerApiImpl() {
}

ServerApiImpl::~ServerApiImpl() {
}

void ServerApiImpl::setSocket(int socket) {
  m_socket = socket;
}

void ServerApiImpl::sendLoginForm() {
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n\r\n"
      << "{\"" D_ITEM_LOGIN "\":\"\",\"" D_ITEM_PASSWORD "\":\"\"}";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::sendRegistrationForm() {
  std::ostringstream oss;
  oss << "HTTP/1.1 200 OK\r\n\r\n"
      << "{\"" D_ITEM_LOGIN "\":\"\",\"" D_ITEM_EMAIL "\":\"\",\"" D_ITEM_PASSWORD "\":\"\"}";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ServerApiImpl::login(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    std::string login = document[ITEM_LOGIN].GetString();
    std::string password = document[ITEM_PASSWORD].GetString();
    LoginForm form(login, password);
    loginPeer(form);
  } else {
    ERR("Login failed: invalid form: %s", json.c_str());
  }
}

void ServerApiImpl::registrate(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());

  if (document.IsObject() &&
      document.HasMember(ITEM_LOGIN) && document[ITEM_LOGIN].IsString() &&
      document.HasMember(ITEM_EMAIL) && document[ITEM_EMAIL].IsString() &&
      document.HasMember(ITEM_PASSWORD) && document[ITEM_PASSWORD].IsString()) {
    std::string login = document[ITEM_LOGIN].GetString();
    std::string email = document[ITEM_EMAIL].GetString();
    std::string password = document[ITEM_PASSWORD].GetString();
    RegistrationForm form(login, email, password);
    registerPeer(form);
  } else {
    ERR("Registration failed: invalid form: %s", json.c_str());
  }
}

void ServerApiImpl::message(const std::string& json) {

}

/* Internals */
// ----------------------------------------------------------------------------
void ServerApiImpl::loginPeer(const LoginForm& form) {

}

void ServerApiImpl::registerPeer(const RegistrationForm& form) {

}

