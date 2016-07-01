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

#ifndef CHAT_SERVER_REQUEST_PREPARE__H__
#define CHAT_SERVER_REQUEST_PREPARE__H__

#include <string>
#include "api/structures.h"
#include "api/types.h"

namespace util {

std::string getLoginForm_request(const std::string& host);
std::string getRegistrationForm_request(const std::string& host);
std::string sendLoginForm_request(const std::string& host, const LoginForm& form);
std::string sendRegistrationForm_request(const std::string& host, const RegistrationForm& form);
std::string sendMessage_request(const std::string& host, const Message& message);
std::string logout_request(const std::string& host, ID_t id, const std::string& name);
std::string switchChannel_request(const std::string& host, ID_t id, int channel, const std::string& name);
std::string isLoggedIn_request(const std::string& host, const std::string& name);
std::string isRegistered_request(const std::string& host, const std::string& name);
std::string getAllPeers_request(const std::string& host);
std::string getAllPeers_request(const std::string& host, int channel);

}

#endif  // CHAT_SERVER_REQUEST_PREPARE__H__

