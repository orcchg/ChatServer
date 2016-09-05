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

#ifndef CHAT_SERVER_COMMON__H__
#define CHAT_SERVER_COMMON__H__

#include <string>
#include <vector>
#include <cstdint>
#include "api/structures.h"
#include "api/types.h"

#define MESSAGE_SIZE 4096
#define USER_MESSAGE_MAX_SIZE 1600

void PRINTR(const char* fmt, ...);

namespace common {

enum PreparseLeniency {
  DISABLED = 0,
  SOFT     = 1,
  STRICT   = 2
};

uint64_t getCurrentTime();

std::string createFilenameWithId(ID_t id, const std::string& filename);
bool isFileAccessible(const std::string& filename);
std::string readFileToString(const std::string& filename);

const std::string& preparse(const std::string& json);
std::string preparse(const std::string& json, PreparseLeniency leniency);
std::string restoreStrippedInMemoryPEM(const std::string& pem);
std::string unwrapJsonObject(const char* field, const std::string& json, PreparseLeniency leniency = PreparseLeniency::DISABLED);

void split(const std::string& input, char delimiter, std::vector<std::string>* output);
bool isNumber(const std::string& str, ID_t& id);

std::string bin2hex(unsigned char* src, size_t size);
void hex2bin(const std::string& source, unsigned char* target, size_t& target_length);

bool isMessageForbidden(const std::string& message);

/* Dictionary */
// ----------------------------------------------------------------------------
class Dictionary {
public:
  Dictionary();
  virtual ~Dictionary();

  std::string getMessage(size_t size) const;

private:
  std::vector<std::string> m_words;
};

Message generateMessage(Dictionary& dictionary, ID_t id);

}

#endif  // CHAT_SERVER_COMMON__H__

