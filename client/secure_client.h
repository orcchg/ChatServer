#ifndef CHAT_SERVER_SECURE_CLIENT__H__
#define CHAT_SERVER_SECURE_CLIENT__H__

#if SECURE

#include "client.h"

class SecureClient : public Client {
public:
  SecureClient(const std::string& config_file);
  virtual ~SecureClient();

protected:

};

#endif  // SECURE

#endif  // CHAT_SERVER_SECURE_CLIENT__H__

