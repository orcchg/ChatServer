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
#include "types.h"

/* HTTP Chat-Server API */
// ----------------------------------------------
/**
 *  Body format: JSON
 *
 *  GET   /login - get login form
 *  POST  /login - send filled login form
 *  DELETE   /logout?id=N&name=str - logout chat
 *
 *  GET   /register - get registration form
 *  POST  /register - send registration form
 *
 *  POST  /message - send message
 *  PUT   /switch_channel?id=N&channel=K&name=str - switch to another channel
 *
 *  terminate code: 99
 */

#define TERMINATE_CODE "99"

enum class Method : int {
  UNKNOWN = -1, GET = 0, POST = 1, PUT = 2, DELETE = 3
};

enum class Path : int {
  UNKNOWN = -1, LOGIN = 0, REGISTER = 1, MESSAGE = 2, LOGOUT = 3, SWITCH_CHANNEL = 4
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

  virtual bool login(const std::string& json) = 0;
  virtual ID_t registrate(const std::string& json) = 0;
  virtual void message(const std::string& json) = 0;
  virtual void logout(const std::string& path) = 0;
  virtual bool switchChannel(const std::string& path) = 0;

  virtual void terminate() = 0;
};

#endif  // CHAT_SERVER_API__H__

