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

void ClientApiImpl::isLoggedIn(const std::string& name) {
  std::string request = util::isLoggedIn_request(m_host, name);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::isRegistered(const std::string& name) {
  std::string request = util::isRegistered_request(m_host, name);
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

void ClientApiImpl::privateRequest(int src_id, int dest_id) {
  std::string request = util::privateRequest_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privateConfirm(int src_id, int dest_id, bool accept) {
  std::string request = util::privateConfirm_request(m_host, src_id, dest_id, accept);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privateAbort(int src_id, int dest_id) {
  std::string request = util::privateAbort_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privatePubKey(int id, const secure::Key& key) {
  std::string request = util::privatePubKey_request(m_host, id, key);
  send(m_socket, request.c_str(), request.length(), 0);
}

void ClientApiImpl::privatePubKeysExchange(int src_id, int dest_id) {
  std::string request = util::privatePubKeysExchange_request(m_host, src_id, dest_id);
  send(m_socket, request.c_str(), request.length(), 0);
}

#endif  // SECURE

