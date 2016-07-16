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

#ifndef CHAT_SERVER_UTILS__H__
#define CHAT_SERVER_UTILS__H__

#include <string>
#include <utility>
#if SECURE
#include "api/icryptor.h"
#endif  // SECURE
#include "api/structures.h"

namespace util {

#if SECURE
struct HandshakeBundle {
  ID_t src_id;
  ID_t dest_id;
  bool accept;
};
#endif  //SECURE

std::string enterSymbolic(const char* title);
std::string enterSymbolic(const char* title, bool hide);
#if SECURE
std::string enterSymbolic(const char* title, secure::ICryptor* cryptor);
std::string enterSymbolic(const char* title, secure::ICryptor* cryptor, bool hide);
#endif  // SECURE
int selectChannel();
bool checkStatus(const std::string& json);
bool checkSystemMessage(const std::string& json, std::string* system, Path& action, ID_t& id);
#if SECURE
PrivateHandshake checkPrivateHandshake(const std::string& json, HandshakeBundle* bundle);
#endif  // SECURE
bool isEmailValid(const std::string& email);

enum class Command : int {
  UNKNOWN = -1,
  DIRECT_MESSAGE = 0,
  SWITCH_CHANNEL = 1,
  LOGOUT = 2,
  MENU = 3
#if SECURE
  , PRIVATE_REQUEST = 4
  , PRIVATE_CONFIRM = 5
  , PRIVATE_REJECT = 6
  , PRIVATE_ABORT = 7
  , PRIVATE_PUBKEY = 8
  , PRIVATE_PUBKEY_EXCHANGE = 9
#endif  // SECURE
};

Command parseCommand(const std::string& command, ID_t& value);

}

#endif  // CHAT_SERVER_UTILS__H__

