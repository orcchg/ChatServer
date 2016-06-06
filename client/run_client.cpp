#include <string>
#include <cstring>
#include "client.h"

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  // read configuration
  std::string config_file = "../client/local.cfg";
  if (argc >= 2) {
    char buffer[256];
    memset(buffer, 0, 256);
    strncpy(buffer, argv[1], strlen(argv[1]));
    config_file = std::string(buffer);
  }
  DBG("Configuration from file: %s", config_file.c_str());

  // start client
  Client client(config_file);
  client.init();
  client.run();
  return 0;
}

