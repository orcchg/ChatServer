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

#ifndef CHAT_SERVER_COMMON__H__
#define CHAT_SERVER_COMMON__H__

#include <string>
#include <cstdint>
#include "api/types.h"

namespace common {

uint64_t getCurrentTime();

std::string createFilenameWithId(ID_t id, const std::string& filename);
bool isFileAccessible(const std::string& filename);
std::string readFileToString(const std::string& filename);

std::string preparse(const std::string& json);
std::string unwrapJsonObject(const char* field, const std::string& json);

}

#endif  // CHAT_SERVER_COMMON__H__

