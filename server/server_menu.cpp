#include <cstdio>
#include <cstring>
#include "logger.h"
#include "server_menu.h"

namespace menu {

const char* HELP = "help";
const char* STOP = "stop";

bool evaluate(Server* server, char* command) {
  if (strcmp(HELP, command) == 0) {
    printHelp();
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
                   \n\tstop - send terminate signal to all peers and stop server\n");
}

void printPrompt() {
  printf("server@server:");
}

}

