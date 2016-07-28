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

#ifndef CHAT_SERVER_CRYPTING_UTIL__H__
#define CHAT_SERVER_CRYPTING_UTIL__H__

#include <string>
#include "api/structures.h"

#if SECURE

#define COMPOUND_MESSAGE_DELIMITER ':'
#define COMPOUND_MESSAGE_DELIMITER_STR ":"
#define COMPOUND_MESSAGE_SEPARATOR "-----*****-----"
#define COMPOUND_MESSAGE_SEPARATOR_LENGTH 15

namespace secure {

std::string encryptAndPack(const secure::Key& public_key, const std::string& plain, bool& encrypted);
std::string unpackAndDecrypt(const secure::Key& private_key, const std::string& chunk, bool& decrypted);

}

#endif  // SECURE

#endif  // CHAT_SERVER_CRYPTING_UTIL__H__
