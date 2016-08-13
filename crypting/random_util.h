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

#ifndef CHAT_SERVER_RANDOM_UTIL__H__
#define CHAT_SERVER_RANDOM_UTIL__H__

#if SECURE

#define PUBLIC_KEY_FILE "public.pem"
#define PRIVATE_KEY_FILE "private.pem"

#include <string>
#include "api/structures.h"

namespace secure {
namespace random {

int setRandomSeed();

std::string generateString(int length);
void generateKeyPair(ID_t id, const char* input, size_t size);
std::pair<Key, Key> loadKeyPair(ID_t id, bool* accessible);
std::pair<Key, Key> getKeyPair(ID_t id);

}
}

#endif  // SECURE

#endif  // CHAT_SERVER_RANDOM_UTIL__H__

