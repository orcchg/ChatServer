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

#if SECURE

#include <sstream>
#include "logger.h"
#include "request_prepare.h"
#include "secure_client_api_impl.h"

SecureClientApiImpl::SecureClientApiImpl(
    BIO* bio,
    const std::string& ip_address,
    const std::string& port)
  : m_bio(nullptr)
  , m_host(ip_address + ":" + port) {
}

SecureClientApiImpl::~SecureClientApiImpl() {
}

void SecureClientApiImpl::getLoginForm() {
  std::string request = util::getLoginForm_request(m_host);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::getRegistrationForm() {
  std::string request = util::getRegistrationForm_request(m_host);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::sendLoginForm(const LoginForm& form) {
  std::string request = util::sendLoginForm_request(m_host, form);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::sendRegistrationForm(const RegistrationForm& form) {
  std::string request = util::sendRegistrationForm_request(m_host, form);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::sendMessage(const Message& message) {
  std::string request = util::sendMessage_request(m_host, message);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::logout(ID_t id, const std::string& name) {
  std::string request = util::logout_request(m_host, id, name);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::switchChannel(ID_t id, int channel, const std::string& name) {
  std::string request = util::switchChannel_request(m_host, id, channel, name);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::isLoggedIn(const std::string& name) {
  std::string request = util::isLoggedIn_request(m_host, name);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::isRegistered(const std::string& name) {
  std::string request = util::isRegistered_request(m_host, name);
  BIO_write(m_bio, request.c_str(), request.length());
}

#endif  // SECURE

