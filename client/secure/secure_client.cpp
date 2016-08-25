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

#if SECURE

#include "logger.h"
#include "secure_client.h"
#include "secure_client_api_impl.h"

/// @see http://www.ibm.com/developerworks/library/l-openssl/
/// @see http://fm4dd.com/openssl/sslconnect.htm
/// @see http://h71000.www7.hp.com/doc/83final/ba554_90007/ch04s03.html

SecureClient::SecureClient(const std::string& config_file)
  : Client(config_file)
  , m_bio(nullptr)
  , m_ssl_context(nullptr)
  , m_ssl(nullptr) {
}

SecureClient::~SecureClient() {
}

/* Init */
// ----------------------------------------------------------------------------
void SecureClient::init() {
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  m_ssl_context = SSL_CTX_new(SSLv23_client_method());

  // loading the Trust Store
  if(!SSL_CTX_load_verify_locations(m_ssl_context, "../client/certs/TrustStore.pem", nullptr)) {
    ERR("Failed to load the Trust Store of certificates: %s", ERR_reason_error_string(ERR_get_error()));
    throw ClientException();
  }

  m_bio = BIO_new_ssl_connect(m_ssl_context);
  if (m_bio == nullptr) {
    ERR("Failed to prepare new secure connection: %s", ERR_reason_error_string(ERR_get_error()));
    throw ClientException();
  }
  BIO_get_ssl(m_bio, &m_ssl);
  SSL_set_mode(m_ssl, SSL_MODE_AUTO_RETRY);  // retry handshake transparently if Server suddenly wants

  // establish secure connection
  BIO_set_conn_hostname(m_bio, m_ip_address.c_str());
  BIO_set_conn_port(m_bio, m_port.c_str());
  if (BIO_do_connect(m_bio) <= 0) {
    ERR("Failed to securely connect to [%s:%s]: %s", m_ip_address.c_str(), m_port.c_str(), ERR_reason_error_string(ERR_get_error()));
    m_is_connected = false;
  } else {
    m_is_connected = true;
  }

  // checking certificate from Server
  if (SSL_get_verify_result(m_ssl) != X509_V_OK) {
    WRN("Certificate verification has failed: %s", ERR_reason_error_string(ERR_get_error()));
    // TODO: probably, proceed further
  }

  INF("Secure connection has been established");
  m_api_impl = new SecureClientApiImpl(m_bio, m_ip_address, m_port);
}

/* Release */
// ----------------------------------------------
void SecureClient::end() {
  DBG("Secure Client closing...");
  m_is_stopped = true;  // stop background receiver thread if any
  ERR_free_strings();
  SSL_CTX_free(m_ssl_context);
  SSL_free(m_ssl);
  BIO_free_all(m_bio);
}

/* Process response */
// ----------------------------------------------
Response SecureClient::getResponse(int socket, bool* is_closed, std::vector<Response>* responses) {
  char buffer[MESSAGE_SIZE];
  memset(buffer, 0, MESSAGE_SIZE);
  int read_bytes = BIO_read(m_bio, buffer, MESSAGE_SIZE);
  if (read_bytes == 0) {
    DBG("Connection closed");
    goto FAILURE;
  } else if (read_bytes < 0) {
    bool retry = BIO_should_retry(m_bio);
    if (!retry) {
      ERR("Failed to retry connection: %s", ERR_reason_error_string(ERR_get_error()));
      goto FAILURE;
    }
  }
  DBG("Raw response: %.*s", (int) read_bytes, buffer);
  return m_parser.parseBufferedResponses(buffer, read_bytes, responses);

  FAILURE:
    *is_closed = true;
    return Response::EMPTY;
}

#endif  // SECURE

