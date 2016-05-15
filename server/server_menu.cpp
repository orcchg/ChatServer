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

#include <cstdio>
#include <cstring>
#include "logger.h"
#include "server_menu.h"

namespace menu {

const char* HELP = "help";
const char* LOGI = "logi";
const char* STOP = "stop";

bool evaluate(Server* server, char* command) {
  if (strcmp(HELP, command) == 0) {
    printHelp();
  } else if (strcmp(LOGI, command) == 0) {
    server->logIncoming();
  } else if (strcmp(STOP, command) == 0) {
    server->stop();
    return false;
  } else {
    WRN("Undefined command: %s", command);
  }
  return true;
}

void printHelp() {
  printf("Commands:\n\thelp - print this help \
                   \n\tlogi - enable / disable incoming requests logging \
                   \n\tstop - send terminate signal to all peers and stop server\n");
}

void printPrompt() {
  printf("server@server:");
}

}

