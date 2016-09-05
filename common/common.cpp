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

#include <algorithm>
#include <chrono>
#include <exception>
#include <fstream>
#include <cstdlib>
#include <stdarg.h>
#include <sstream>
#include <sys/stat.h>
#include "common.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

/*void PRINTR(const char* format, ...) {
#if ENABLED_LOGGING
  va_list argptr;
  va_start(argptr, format);
  printf(format, argptr);
  va_end(argptr);
#endif  // ENABLED_LOGGING
}*/

namespace common {

uint64_t getCurrentTime() {
  auto now = std::chrono::system_clock::now();
  auto duration = now.time_since_epoch();
  auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
  return millis;
}

std::string createFilenameWithId(ID_t id, const std::string& filename) {
  std::ostringstream oss;
  oss << "id_" << id << "_" << filename;
  return oss.str();
}

/**
 *  Efficient solutions.
 *
 *  @see http://stackoverflow.com/questions/12774207/fastest-way-to-check-if-a-file-exist-using-standard-c-c11-c
 *  @see http://stackoverflow.com/questions/2602013/read-whole-ascii-file-into-c-stdstring
 */
bool isFileAccessible(const std::string& filename) {
  struct stat buffer;
  return (stat(filename.c_str(), &buffer) == 0);
}

std::string readFileToString(const std::string& filename) {
  if (!isFileAccessible(filename)) {
    ERR("File is not accessible: %s", filename.c_str());
    return "";
  }
  std::ifstream fin(filename, std::fstream::in);
  fin.seekg(0, std::ios::end);
  size_t size = fin.tellg();
  std::string buffer(size, ' ');
  fin.seekg(0);
  fin.read(&buffer[0], size);
  fin.close();
  return buffer;
}

const std::string& preparse(const std::string& json) {
  return json;
}

std::string preparse(const std::string& json, PreparseLeniency leniency) {
  if (leniency == PreparseLeniency::DISABLED) {
    return json;
  }

  std::string result = json;  // copy
  switch (leniency) {
    case STRICT:
      result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
    case SOFT:
      result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
      break;
  }
  return result;
}

std::string restoreStrippedInMemoryPEM(const std::string& pem) {
  char* buffer = new char[pem.length() + 80];
  memset(buffer, 0, pem.length() + 80);

  size_t i1 = pem.find("RSA", 5);
  if (i1 == std::string::npos) {
    ERR("Input string not in PEM format!");
    return pem;
  }
  size_t i2 = pem.find("KEY", i1 + 3) + 8;
  strncpy(buffer, pem.substr(0, i2).c_str(), i2);
  buffer[i2] = '\n';
  ++i2;

  size_t k = 1;
  size_t i3 = pem.find("END", i2) - 5;
  while (i2 + 64 < i3) {
    strncpy(buffer + i2, pem.substr(i2 - k, 64).c_str(), 64);
    i2 += 64;
    buffer[i2] = '\n';
    ++i2;
    ++k;
  }
  if (i2 != i3) {
    int rest_length = i3 - i2 + k;
    std::string rest = pem.substr(i2 - k, rest_length);
    strncpy(buffer + i2, rest.c_str(), rest.length());
    i2 += rest_length;
  }
  buffer[i2] = '\n';
  ++i2;
  std::string tail = pem.substr(i3);
  strncpy(buffer + i2, tail.c_str(), tail.length());
  DBG("%s", buffer);

  std::string answer(buffer);
  delete [] buffer;  buffer = nullptr;
  return answer;
}

std::string unwrapJsonObject(const char* field, const std::string& json, PreparseLeniency leniency) {
  rapidjson::Document document;
  auto prepared_json = common::preparse(json, leniency);
  document.Parse(prepared_json.c_str());

  if (document.IsObject() &&
      document.HasMember(field) && document[field].IsObject()) {
    std::ostringstream oss;
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
    document[field].Accept(writer);
    oss << sb.GetString();
    std::string substr = oss.str();
    TRC("Unwrapped sub-object: %s", substr.c_str());
    return substr;
  } else {
    ERR("Input JSON has no field [%s], json: %s", field, json.c_str());
  }
  return json;
}

void split(const std::string& input, char delimiter, std::vector<std::string>* output) {
  std::stringstream ss(input);
  std::string item;
  while (std::getline(ss, item, delimiter)) {
    output->push_back(item);
    TRC("Split token: %s", item.c_str());
  }
}

// ----------------------------------------------------------------------------
static int char2int(char input) {
  if (input >= '0' && input <= '9') {
    return input - '0';
  }
  if (input >= 'A' && input <= 'F') {
    return input - 'A' + 10;
  }
  if (input >= 'a' && input <= 'f') {
    return input - 'a' + 10;
  }
  ERR("Invalid char: %c", input);
  throw std::invalid_argument("Invalid input string");
}

std::string bin2hex(unsigned char* src, size_t size) {
  std::ostringstream oss;
  for (size_t i = 0; i < size; ++i) {
    int value = static_cast<int>(src[i]);
    if (value < 16) {
      oss << '0';
    }
    oss << std::hex << value;
  }
  return oss.str();
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex2bin(const std::string& source, unsigned char* target, size_t& target_length) {
  if (source.length() < 2) {
    throw std::invalid_argument("Input string must have even number of [0-9a-f] characters");
  }
  target_length = 0;
  for (size_t i = 0; i < source.length(); i += 2, ++target_length) {
     *(target++) = char2int(source[i]) * 16 + char2int(source[i + 1]);
  }
}

// ----------------------------------------------------------------------------
bool isMessageForbidden(const std::string& message) {
  /* Logic to forbid some content in message */
  if (message.find_first_of("\\") != std::string::npos || message.find("HTTP/") != std::string::npos) {
    WRN("Forbidden substring in message: %s", message.c_str());
    return true;
  }
  // extendable further
  return false;
}

/* Dictionary */
// ----------------------------------------------------------------------------
static const char* text = "Lorem ipsum dolor sit amet consectetur adipiscing elit Nulla mollis elit ac tincidunt scelerisque Vivamus scelerisque sem velit Fusce eget felis massa Cras eget arcu nec magna iaculis tempus nec et magna Interdum et malesuada fames ac ante ipsum primis in faucibus Integer eleifend lacus mauris eget dapibus lacus porttitor ut Donec sit amet faucibus mauris ac condimentum nisl Vestibulum consequat quis nisl eu faucibus Suspendisse tempor turpis vel magna mollis ut ultrices augue ultrices Etiam eu leo in velit pulvinar faucibus Ut ut fringilla justo Maecenas vel dictum mi Vivamus elementum sollicitudin rutrum Pellentesque eros eros tristique posuere consequat et facilisis at nulla.Suspendisse potenti Nunc odio sapien malesuada non ultrices vitae tempor a ex Vivamus sodales est dolor et congue nunc accumsan ut Mauris arcu nisi scelerisque eget volutpat eleifend porta id nisl Curabitur quam magna ullamcorper ut hendrerit vel aliquet nec nulla Nullam vitae orci porta tellus viverra rutrum eget quis lorem Maecenas facilisis laoreet lacus ac semper libero ullamcorper nec Nullam vestibulum felis in metus ullamcorper tempus Nam odio dui imperdiet id nisi eget porttitor lacinia dolor Fusce mattis ligula ac leo maximus porta Nulla vitae urna nisl Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas Sed ut lacus ultrices porta magna quis posuere elit Mauris sollicitudin metus in vehicula mattis Maecenas a massa vel est interdum tempus eu et magna Quisque ultricies tincidunt turpis at elementum Pellentesque suscipit mi id tortor dictum eget congue velit pellentesque Fusce non nulla sit amet ante semper pharetra Nunc at justo faucibus eleifend purus ut egestas tellus Vestibulum quis luctus nunc Duis id finibus lorem Sed dignissim ex in efficitur vestibulum Vivamus posuere consectetur quam a sodales Phasellus a ante eu nibh ullamcorper porta et quis est Aliquam in scelerisque ex Curabitur ornare ligula eros et egestas nisl accumsan ac Curabitur non efficitur erat a dapibus ipsum Phasellus tristique tortor sit amet lacus faucibus sed elementum orci vulputate Nunc nec urna justo Aliquam dictum nulla varius euismod sapien sed placerat ex Integer vitae porta est Sed sit amet sem massa Duis faucibus nulla vitae efficitur convallis mauris risus dapibus arcu a rutrum purus odio faucibus arcu Donec suscipit leo ac vehicula lobortis nisl lacus rutrum justo id sodales nibh dolor tempor ipsum Ut quis dignissim justo sed pulvinar risus Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae Aenean ut neque ut ligula iaculis pellentesque eu sed risus Sed facilisis erat vitae libero faucibus ullamcorper Nam ut ex ullamcorper iaculis tortor at scelerisque erat Aliquam dictum lorem a viverra ultrices Nullam ut faucibus ante vel placerat odio Etiam efficitur magna at dui tincidunt non mollis tellus pulvinar Suspendisse sed diam sed massa mollis ornare eu eget nibh Nulla nisi leo congue quis purus vel pulvinar porta ex In auctor turpis a velit facilisis faucibus Sed a erat magna Aliquam faucibus tristique metus ac sollicitudin Suspendisse tempus mauris dapibus diam luctus at aliquet est porttitor Donec consectetur libero felis vel sagittis \n";

Dictionary::Dictionary() {
  TRC("Dictionary ctor()");
  std::istringstream iss(text);
  std::string word;
  while (iss >> word) {
    m_words.emplace_back(word);
  }
  std::sort(m_words.begin(), m_words.end());
  auto lambda = [](std::string& s1, std::string& s2) { return (s1.compare(s2) == 0 ? true : false); };
  m_words.erase(std::unique(m_words.begin(), m_words.end(), lambda), m_words.end());
}

Dictionary::~Dictionary() {
  TRC("Dictionary ~dtor()");
}

std::string Dictionary::getMessage(size_t size) const {
  size_t new_size = size > m_words.size() ? m_words.size() : size;
  std::ostringstream oss;
  const char* delimiter = "";
  for (size_t i = 0; i < new_size; ++i) {
    size_t index = rand() % m_words.size();
    oss << delimiter << m_words[index];
    delimiter = " ";
  }
  return oss.str();
}

Message generateMessage(Dictionary& dictionary, ID_t id) {
  size_t size = rand() % 500 + 1;
  std::string message = dictionary.getMessage(size);
  return Message::Builder(id).setLogin("login").setEmail("email@ya.ru").setChannel(0)
      .setDestId(0).setTimestamp(1000000000).setSize(size)
      .setEncrypted(false).setMessage(message)
      .build();
}

}

