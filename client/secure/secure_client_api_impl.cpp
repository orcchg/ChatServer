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

void SecureClientApiImpl::logout(ID_t id) {
  std::string request = util::logout_request(m_host, id);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::switchChannel(ID_t id, int channel) {
  std::string request = util::switchChannel_request(m_host, id, channel);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::getPeerId(const std::string& name) {
  std::string request = util::getPeerId_request(m_host, name);
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

void SecureClientApiImpl::checkAuth(const std::string& name, const std::string& password, bool encrypted) {
  std::string request = util::checkAuth_request(m_host, name, password, encrypted);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::kickByAuth(const std::string& name, const std::string& password, bool encrypted) {
  std::string request = util::kickByAuth_request(m_host, name, password, encrypted);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::getAllPeers() {
  std::string request = util::getAllPeers_request(m_host);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::getAllPeers(int channel) {
  std::string request = util::getAllPeers_request(m_host, channel);
  BIO_write(m_bio, request.c_str(), request.length());
}

/* Private secure communication */
// ----------------------------------------------------------------------------
void SecureClientApiImpl::privateRequest(ID_t src_id, ID_t dest_id) {
  std::string request = util::privateRequest_request(m_host, src_id, dest_id);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::privateConfirm(ID_t src_id, ID_t dest_id, bool accept) {
  std::string request = util::privateConfirm_request(m_host, src_id, dest_id, accept);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::privateAbort(ID_t src_id, ID_t dest_id) {
  std::string request = util::privateAbort_request(m_host, src_id, dest_id);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::privatePubKey(ID_t id, const secure::Key& key) {
  std::string request = util::privatePubKey_request(m_host, id, key);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::privatePubKeysExchange(ID_t src_id, ID_t dest_id) {
  std::string request = util::privatePubKeysExchange_request(m_host, src_id, dest_id);
  BIO_write(m_bio, request.c_str(), request.length());
}

/* Administrating */
// ----------------------------------------------------------------------------
void SecureClientApiImpl::sendKickRequest(ID_t src_id, ID_t dest_id) {
  std::string request = util::sendKickRequest_request(m_host, src_id, dest_id);
  BIO_write(m_bio, request.c_str(), request.length());
}

void SecureClientApiImpl::sendAdminRequest(ID_t src_id, const std::string& cert) {
  std::string request = util::sendAdminRequest_request(m_host, src_id, cert);
  BIO_write(m_bio, request.c_str(), request.length());
}

#endif  // SECURE

