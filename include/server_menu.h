#ifndef CHAR_SERVER_SERVER_MENU__H__
#define CHAR_SERVER_SERVER_MENU__H__

#include "server.h"

namespace menu {

bool evaluate(Server* server, char* command);
void printHelp();
void printPrompt();

}

#endif  // CHAR_SERVER_SERVER_MENU__H__

