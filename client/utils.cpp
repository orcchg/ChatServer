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

#include <chrono>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include "api/api.h"
#include "rapidjson/document.h"
#include "utils.h"

namespace util {

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

bool checkStatus(const std::string& json) {
  rapidjson::Document document;
  document.Parse(json.c_str());
  return document.IsObject() &&
      document.HasMember(ITEM_CODE) && document[ITEM_CODE].IsInt() &&
      document.HasMember(ITEM_ID) && document[ITEM_ID].IsInt64();
}

bool checkSystemMessage(const std::string& json, std::string* system) {
  rapidjson::Document document;
  document.Parse(json.c_str());
  bool result = document.IsObject() &&
         document.HasMember(ITEM_SYSTEM) && document[ITEM_SYSTEM].IsString();
  if (result) {
    *system = document[ITEM_SYSTEM].GetString();
  }
  return result;
}

Command parseCommand(const std::string& command, ID_t& value) {
  if (command.length() > 1 && command[0] == '.') {
    int i1 = command.find_first_of(' ');
    std::string argument = command.substr(i1 + 1);
    std::istringstream iss(argument);
    iss >> value;
    switch (command[1]) {
      case 'd': return Command::DIRECT_MESSAGE;
      case 's': return Command::SWITCH_CHANNEL;
      case 'q': return Command::LOGOUT;
      case 'm': return Command::MENU;
    }
  }
  return Command::UNKNOWN;
}

}

