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

#include <sstream>
#include "all.h"
#include "client_api_impl.h"

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
  std::ostringstream oss;
  oss << "GET " D_PATH_LOGIN " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ClientApiImpl::getRegistrationForm() {
  std::ostringstream oss;
  oss << "GET " D_PATH_REGISTER " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ClientApiImpl::sendLoginForm(const std::string& json) {
  std::ostringstream oss;
  oss << "POST " D_PATH_LOGIN " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n" << json;
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ClientApiImpl::sendRegistrationForm(const std::string& json) {
  std::ostringstream oss;
  oss << "POST " D_PATH_REGISTER " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n" << json;
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ClientApiImpl::sendMessage(const std::string& json) {
  std::ostringstream oss;
  oss << "POST " D_PATH_MESSAGE " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n" << json;
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ClientApiImpl::logout(const std::string& path) {
  std::ostringstream oss;
  oss << "DELETE " << path << " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

void ClientApiImpl::switchChannel(const std::string& path) {
  std::ostringstream oss;
  oss << "PUT " << path << " HTTP/1.1\r\nHost: " << m_host << "\r\n\r\n";
  send(m_socket, oss.str().c_str(), oss.str().length(), 0);
}

