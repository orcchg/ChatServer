#if SECURE

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "secure_client.h"

SecureClient::SecureClient(const std::string& config_file)
  : Client(config_file) {
}

SecureClient::~SecureClient() {
}

/* Init */
// ----------------------------------------------------------------------------
void SecureClient::init() {
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
}

/* Release */
// ----------------------------------------------
void SecureClient::end() {
}

#endif  // SECURE

