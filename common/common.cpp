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

#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include "common.h"
#include "logger.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

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

}

