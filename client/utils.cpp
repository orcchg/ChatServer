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

#include <chrono>
#include <cstdio>
#include <cctype>
#include <sstream>
#include <iostream>
#include <regex>
#include <termios.h>
#include <unistd.h>
#include "api/api.h"
#include "common.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "utils.h"

namespace util {

const char* EMAIL_REGEX_PATTERN = "\\^[a-zA-Z0-9][a-zA-Z0-9\\_.]+@[a-zA-Z0-9_]+.[a-zA-Z0-9_.]+\\$";

static void hideStdin() {
  termios old_terminal;
  tcgetattr(STDIN_FILENO, &old_terminal);
  old_terminal.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

static void showStdin() {
  termios old_terminal;
  tcgetattr(STDIN_FILENO, &old_terminal);
  old_terminal.c_lflag |= ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

std::string enterSymbolic(const char* title) {
  return enterSymbolic(title, false);
}

std::string enterSymbolic(const char* title, bool hide) {
  if (hide) {
    hideStdin();
  }
  printf("%s: ", title);
  std::string str;
  std::cin >> str;
  if (hide) {
    showStdin();
  }
  return str;
}

#if SECURE

std::string enterSymbolic(const char* title, secure::ICryptor* cryptor) {
  return enterSymbolic(title, cryptor, false);
}

std::string enterSymbolic(const char* title, secure::ICryptor* cryptor, bool hide) {
  if (hide) {
    hideStdin();
  }
  printf("%s: ", title);
  std::string str;
  std::cin >> str;
  if (hide) {
    showStdin();
  }
  return cryptor->encrypt(str);
}

#endif  // SECURE

int selectChannel() {
  printf("Select channel: ");
  int channel = 0;
  std::cin >> channel;
  return channel;
}

bool checkCheck(const std::string& json, bool& check, Path& action, ID_t& id) {
  action = Path::UNKNOWN;
  id = UNKNOWN_ID;
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());
  bool result = document.IsObject() &&
      document.HasMember(ITEM_CHECK) && document[ITEM_CHECK].IsInt();
  if (result) {
    check = document[ITEM_CHECK].GetInt() != 0;
    if (document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
        document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
      action = static_cast<Path>(document[ITEM_ACTION].GetInt());
      id = document[ITEM_ID].GetInt64();
    } else {
      DBG("Check json has no action and peer's id");
    }
  }
  return result;
}

bool checkStatus(const std::string& json, StatusCode& status) {
  status = StatusCode::UNKNOWN;
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());
  bool result = document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64();
  if (result) {
    status = static_cast<StatusCode>(document[ITEM_CODE].GetInt());
  }
  return result;
}

bool checkSystemMessage(
    const std::string& json,
    std::string* system,
    std::string* payload,
    Path& action,
    ID_t& id) {
  action = Path::UNKNOWN;
  id = UNKNOWN_ID;
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());
  bool result = document.IsObject() &&
      document.HasMember(ITEM_SYSTEM) && document[ITEM_SYSTEM].IsString();
  if (result) {
    *system = document[ITEM_SYSTEM].GetString();
    if (document.HasMember(ITEM_ACTION) && document[ITEM_ACTION].IsInt() &&
        document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64()) {
      action = static_cast<Path>(document[ITEM_ACTION].GetInt());
      id = document[ITEM_ID].GetInt64();
    } else {
      DBG("System message json has no action and peer's id");
    }
    if (document.HasMember(ITEM_PAYLOAD) && document[ITEM_PAYLOAD].IsString()) {
      *payload = document[ITEM_PAYLOAD].GetString();
    } else {
      DBG("System message json has no payload");
    }
  }
  return result;
}

#if SECURE

static void fillHandshakeBundle(const rapidjson::Value& object, HandshakeBundle* bundle) {
  if (bundle == nullptr) {
    TRC("Bundle not allocated!");
    return;
  }
  if (object.IsObject() &&
      object.HasMember(ITEM_SRC_ID) && object[ITEM_SRC_ID].IsInt64() &&
      object.HasMember(ITEM_DEST_ID) && object[ITEM_DEST_ID].IsInt64()) {
    bundle->src_id = object[ITEM_SRC_ID].GetInt64();
    bundle->dest_id = object[ITEM_DEST_ID].GetInt64();
    if (object.HasMember(ITEM_ACCEPT) && object[ITEM_ACCEPT].IsInt()) {
      bundle->accept = object[ITEM_ACCEPT].GetInt();
    }
  } else {
    TRC("Object is not a handshake structure");
  }
}

static void fillHandshakeBundleOnlyId(const rapidjson::Value& object, HandshakeBundle* bundle) {
  if (bundle == nullptr) {
    TRC("Bundle not allocated!");
    return;
  }
  if (object.IsObject() &&
      object.HasMember(ITEM_ID) && object[ITEM_ID].IsInt64()) {
      bundle->dest_id = object[ITEM_ID].GetInt64();
  } else {
    TRC("Object is not a handshake structure");
  }
}

PrivateHandshake checkPrivateHandshake(const std::string& json, HandshakeBundle* bundle) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json);
  document.Parse(prepared_json.c_str());
  if (document.IsObject()) {
    if (document.HasMember(ITEM_PRIVATE_REQUEST)) {
      DBG("Handshake: request");
      fillHandshakeBundle(document[ITEM_PRIVATE_REQUEST], bundle);
      return PrivateHandshake::REQUEST;
    } else if (document.HasMember(ITEM_PRIVATE_CONFIRM)) {
      DBG("Handshake: confirm");
      fillHandshakeBundle(document[ITEM_PRIVATE_CONFIRM], bundle);
      return PrivateHandshake::CONFIRM;
    } else if (document.HasMember(ITEM_PRIVATE_ABORT)) {
      DBG("Handshake: abort");
      fillHandshakeBundle(document[ITEM_PRIVATE_ABORT], bundle);
      return PrivateHandshake::ABORT;
    } else if (document.HasMember(ITEM_PRIVATE_PUBKEY)) {
      DBG("Handshake: pubkey");
      fillHandshakeBundleOnlyId(document[ITEM_PRIVATE_PUBKEY], bundle);
      return PrivateHandshake::PUBKEY;
    }
  }
  DBG("Json is not related to private handshake: %s", json.c_str());
  return PrivateHandshake::UNKNOWN;
}

#endif  // SECURE

bool isEmailValid(const std::string& email) {
  /*try {
    auto pattern = std::regex(EMAIL_REGEX_PATTERN);
    return std::regex_match(email, pattern);
  } catch (std::regex_error) {
    ERR("Regular expressions aren't supported. Using simple verification...");*/
    return email.find('@') != std::string::npos;
  /*}*/
}

Command parseCommand(const std::string& command, ID_t& value, std::string* payload) {
  if (command.length() > 1 && command[0] == '.') {
    int i1 = command.find_first_of(' ');
    *payload = command.substr(i1 + 1);
    std::istringstream iss(*payload);
    ID_t id = UNKNOWN_ID;
    if (common::isNumber(*payload, id)) {
      iss >> value;
    }
    switch (command[1]) {
      case 'd': return Command::DIRECT_MESSAGE;
      case 's': return Command::SWITCH_CHANNEL;
      case 'q': return Command::LOGOUT;
      case 'm': return Command::MENU;
#if SECURE
      case 'p':
        if (command.length() > 2) {
          switch (command[2]) {
            case 'r': return Command::PRIVATE_REQUEST;
            case 'c': return Command::PRIVATE_CONFIRM;
            case 'd': return Command::PRIVATE_REJECT;
            case 'x': return Command::PRIVATE_ABORT;
            case 'e': return Command::PRIVATE_PUBKEY_EXCHANGE;
            case 'k': return Command::PRIVATE_PUBKEY;
          }
        }
        break;
#endif  // SECURE
      case 'i': return Command::PEER_ID;
      case 'x': return Command::KICK;
#if SECURE
      case 'a': return Command::ADMIN_REQUEST;
#endif
    }
  }
  return Command::UNKNOWN;
}

}

