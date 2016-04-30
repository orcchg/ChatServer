#if SECURE

#include <string>
#include <cstring>
#include "secure_client.h"

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  // read configuration
  std::string config_file = "../client/local.cfg";
  if (argc >= 2) {
    char buffer[256];
    strncpy(buffer, argv[1], strlen(argv[1]));
    config_file = std::string(buffer);
  }
  DBG("Configuration from file: %s", config_file.c_str());

  // start client
  SecureClient s_client(config_file);
  s_client.init();
  s_client.run();
  return 0;
}

#else  // SECURE

int main(int argc, char** argv) {
  ERR("Secure Client is not supported. Rebuild with -DSECURE=true");
  return 1;
}

#endif  // SECURE

