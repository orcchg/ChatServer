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
#if SECURE
const char* PRIV = "priv";
#endif  // SECURE
const char* STOP = "stop";

static bool evaluateKick(const std::string& command, ID_t& id) {
  id = UNKNOWN_ID;
  if (command.length() >= 6 &&
      command[0] == 'k' && command[1] == 'i' && command[2] == 'c' && command[3] == 'k') {
    int i1 = command.find_last_of(' ');
    if (i1 != std::string::npos) {
      id = std::stoll(command.substr(i1 + 1));
      return true;
    }
  }
  return false;
}

bool evaluate(Server* server, const std::string& command) {
  ID_t id = UNKNOWN_ID;
  if (strcmp(HELP, command.c_str()) == 0) {
    printHelp();
  } else if (evaluateKick(command, id)) {
    server->kick(id);
  } else if (strcmp(LOGI, command.c_str()) == 0) {
    server->logIncoming();
  } else if (strcmp(LIST, command.c_str()) == 0) {
    server->listAllPeers();
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
  printf("Commands:\n\t%s - print this help \
                   \n\t%s - force logout peer with <id> \
                   \n\t%s - enable / disable incoming requests logging \
                   \n\t%s - list all logged in peers", HELP, KICK, LOGI, LIST);
#if SECURE
  printf("\n\t%s - show list of private communications", PRIV);
#endif  // SECURE
  printf("\n\t%s - send terminate signal to all peers and stop server\n", STOP);
}

void printPrompt() {
  printf("server@server:");
}

}

