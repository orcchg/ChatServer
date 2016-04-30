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

#ifndef CHAT_SERVER_SECURE_CLIENT__H__
#define CHAT_SERVER_SECURE_CLIENT__H__

#if SECURE

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "client.h"

class SecureClient : public Client {
public:
  SecureClient(const std::string& config_file);
  virtual ~SecureClient();

  void init() override;

protected:
  BIO* m_bio;
  SSL_CTX* m_ssl_context;
  SSL* m_ssl;  // ssl connection structure

  Response getResponse(int socket, bool* is_closed) override;
  void end() override;
};

#endif  // SECURE

#endif  // CHAT_SERVER_SECURE_CLIENT__H__

