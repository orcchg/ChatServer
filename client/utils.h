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
bool checkCheck(const std::string& json, bool& check, Path& action, ID_t& id);
bool checkStatus(const std::string& json, StatusCode& status);
bool checkSystemMessage(const std::string& json, std::string* system, std::string* payload, Path& action, ID_t& id);
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
  , PEER_ID = 10
  , KICK = 11
  , ADMIN_REQUEST = 12
};

Command parseCommand(const std::string& command, ID_t& value, std::string* payload);

}

#endif  // CHAT_SERVER_UTILS__H__

