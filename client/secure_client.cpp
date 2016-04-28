#if SECURE

#include "secure_client.h"

SecureClient::SecureClient(const std::string& config_file)
  : Client(config_file) {
}

SecureClient::~SecureClient() {
}

#endif  // SECURE

