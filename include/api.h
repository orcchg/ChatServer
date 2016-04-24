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

#ifndef CHAT_SERVER_API__H__
#define CHAT_SERVER_API__H__

#include <string>

/* HTTP Chat-Server API */
// ----------------------------------------------
/**
 *  Body format: JSON
 *
 *  GET   /login - get login form
 *  POST  /login - send filled login form
 *
 *  GET   /register - get registration form
 *  POST  /register - send registration form
 *
 */

enum class Method : int {
  UNKNOWN = -1, GET = 0, POST = 1
};

enum class Path : int {
  UNKNOWN = -1, LOGIN = 0, REGISTER = 1, MESSAGE = 2
};

/* Internal implementation API */
// ----------------------------------------------------------------------------
class LoginForm {
public:
  LoginForm(
    const std::string& login,
    const std::string& password);

protected:
  std::string m_login;
  std::string m_password;
};

class RegistrationForm : public LoginForm {
public:
  RegistrationForm(
    const std::string& login,
    const std::string& email,
    const std::string& password);

protected:
  std::string m_email;
};

/* Client API */
// ----------------------------------------------
class ClientApi {
public:
  virtual void getLoginForm() = 0;
  virtual void getRegistrationForm() = 0;
};

/* Server API */
// ----------------------------------------------
class ServerApi {
public:
  virtual void setSocket(int socket) = 0;

  virtual void sendLoginForm() = 0;
  virtual void sendRegistrationForm() = 0;

  virtual void login(const std::string& json) = 0;
  virtual void registrate(const std::string& json) = 0;
  virtual void message(const std::string& json) = 0;
};

#endif  // CHAT_SERVER_API__H__

