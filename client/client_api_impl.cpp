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

#include <sys/socket.h>
#include "client_api_impl.h"
#include "request_prepare.h"

/* Client implementation */
// ----------------------------------------------------------------------------
ClientApiImpl::ClientApiImpl(
    int socket,
    const std::string& ip_address,
    const std::string& port)
  : m_socket(socket)
  , m_host(ip_address + ":" + port) {
}

ClientApiImpl::~ClientApiImpl() {
}

void ClientApiImpl::getLoginForm() {
  std::string request = util::getLoginForm_request(m_host);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::getRegistrationForm() {
  std::string request = util::getRegistrationForm_request(m_host);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::sendLoginForm(const LoginForm& form) {
  std::string request = util::sendLoginForm_request(m_host, form);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::sendRegistrationForm(const RegistrationForm& form) {
  std::string request = util::sendRegistrationForm_request(m_host, form);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::sendMessage(const Message& message) {
  std::string request = util::sendMessage_request(m_host, message);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::logout(ID_t id) {
  std::string request = util::logout_request(m_host, id);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::switchChannel(ID_t id, int channel) {
  std::string request = util::switchChannel_request(m_host, id, channel);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::getPeerId(const std::string& name) {
  std::string request = util::getPeerId_request(m_host, name);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::isLoggedIn(const std::string& name) {
  std::string request = util::isLoggedIn_request(m_host, name);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::isRegistered(const std::string& name) {
  std::string request = util::isRegistered_request(m_host, name);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::checkAuth(const std::string& name, const std::string& password, bool encrypted) {
  std::string request = util::checkAuth_request(m_host, name, password, encrypted);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::kickByAuth(const std::string& name, const std::string& password, bool encrypted) {
  std::string request = util::kickByAuth_request(m_host, name, password, encrypted);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::getAllPeers() {
  std::string request = util::getAllPeers_request(m_host);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::getAllPeers(int channel) {
  std::string request = util::getAllPeers_request(m_host, channel);
  send(m_socket, request.c_str(), request.length(), 0);
}

/* Private secure communication */
// ----------------------------------------------------------------------------
#if SECURE

void ClientApiImpl::privateRequest(ID_t src_id, ID_t dest_id) {
  std::string request = util::privateRequest_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privateConfirm(ID_t src_id, ID_t dest_id, bool accept) {
  std::string request = util::privateConfirm_request(m_host, src_id, dest_id, accept);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privateAbort(ID_t src_id, ID_t dest_id) {
  std::string request = util::privateAbort_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privatePubKey(ID_t id, const secure::Key& key) {
  std::string request = util::privatePubKey_request(m_host, id, key);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privatePubKeysExchange(ID_t src_id, ID_t dest_id) {
  std::string request = util::privatePubKeysExchange_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

#endif  // SECURE

/* Administrating */
// ----------------------------------------------------------------------------
void ClientApiImpl::sendKickRequest(ID_t src_id, ID_t dest_id) {
  std::string request = util::sendKickRequest_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::sendAdminRequest(ID_t src_id, const std::string& cert) {
  std::string request = util::sendAdminRequest_request(m_host, src_id, cert);
  send(m_socket, request.c_str(), request.length(), 0);
}

