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

#include <string>
#include <cstdio>
#include <cstring>
#include "logger.h"
#include "server_menu.h"

namespace menu {

const char* HELP = "help";
const char* KICK = "kick";
const char* LOGI = "logi";
const char* LIST = "list";
const char* MESG = "mesg";
#if SECURE
const char* PRIV = "priv";
#endif  // SECURE
const char* STOP = "stop";

static bool evaluateKick(const std::string& command, ID_t& id) {
  id = UNKNOWN_ID;
  if (command.length() >= 6 &&
      command[0] == KICK[0] && command[1] == KICK[1] && command[2] == KICK[2] && command[3] == KICK[3]) {
    int i1 = command.find_last_of(' ');
    if (i1 != std::string::npos) {
      id = std::stoll(command.substr(i1 + 1));
      return true;
    }
  }
  return false;
}

static bool evaluateMessage(const std::string& command, ID_t& id, char*& message) {
  id = UNKNOWN_ID;
  if (command.length() >= 6 &&
      command[0] == MESG[0] && command[1] == MESG[1] && command[2] == MESG[2] && command[3] == MESG[3]) {
    int i1 = command.find_first_of(' ');
    int i2 = command.find_last_of('#');
    if (i1 != std::string::npos) {
      size_t size = command.length() - i1;
      if (i2 != std::string::npos) {
        size -= command.length() - i2 + 1;
        id = std::stoll(command.substr(i2 + 1));
      }
      size %= 1024;
      message = new char[size + 4];
      memset(message, '\0', size + 4);
      memcpy(message, command.c_str() + i1 + 1, size);
      DBG("Message[%lli]: %s", id, message);
      return true;
    }
  }
  return false;
}

bool evaluate(Server* server, const std::string& command) {
  ID_t id = UNKNOWN_ID;
  char* message = nullptr;
  if (strcmp(HELP, command.c_str()) == 0) {
    printHelp();
  } else if (evaluateKick(command, id)) {
    server->kick(id);
  } else if (strcmp(LOGI, command.c_str()) == 0) {
    server->logIncoming();
  } else if (strcmp(LIST, command.c_str()) == 0) {
    server->listAllPeers();
  } else if (evaluateMessage(command, id, message)) {
    server->sendMessage(id, message);
    delete [] message;  message = nullptr;
#if SECURE
  } else if (strcmp(PRIV, command.c_str()) == 0) {
    server->listPrivateCommunications();
#endif  // SECURE
  } else if (strcmp(STOP, command.c_str()) == 0) {
    server->stop();
    return false;
  } else {
    WRN("Undefined command: %s", command.c_str());
  }
  return true;
}

void printHelp() {
  printf("\e[5;00;33m\t***    Chat Server " D_VERSION "    ***\t\e[m\n");
  printf("Commands:\n\t%s - print this help \
                   \n\t%s - force logout peer with <id> \
                   \n\t%s - enable / disable incoming requests logging \
                   \n\t%s - list all logged in peers \
                   \n\t%s - broadcast system message to all peers", HELP, KICK, LOGI, LIST, MESG);
#if SECURE
  printf("\n\t%s - show list of private communications", PRIV);
#endif  // SECURE
  printf("\n\t%s - send terminate signal to all peers and stop server\n", STOP);
}

void printPrompt() {
  printf("server@server:");
}

}

