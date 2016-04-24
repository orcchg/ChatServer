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

#include <cstring>
#include "logger.h"
#include "protocol.h"

bool Protocol::operator == (const Protocol& rhs) const {
  return ((src_id == rhs.src_id) &&
       (dest_id == rhs.dest_id) &&
       (channel == rhs.channel) &&
       (timestamp == rhs.timestamp) &&
       (name == rhs.name) &&
       (message == rhs.message));
}

bool Protocol::operator != (const Protocol& rhs) const {
  return !(*this == rhs);
}

/* Serialization */
// ----------------------------------------------------------------------------
char* serialize(const Protocol& message) {
  /**
   * 6 - 5 delimiters '#' and single '\0'
   * 30 - 3 integers (MAX_INT)
   * 13 - 1 long long
   * 2 - possible minus signs 
   *
   * 6 + 20 + 13 + 2 = 51
   */
  char* output = new char[51 + message.name.length() + message.message.length()];

  std::string src_id_src = std::to_string(message.src_id);
  std::string dest_id_src = std::to_string(message.dest_id);
  std::string channel_src = std::to_string(message.channel);  // channel to string
  std::string ts_src = std::to_string(message.timestamp);

  strncpy(output, src_id_src.c_str(), src_id_src.length());
  output += src_id_src.length();
  strncpy(output, "#", 1);
  output += 1;

  strncpy(output, dest_id_src.c_str(), dest_id_src.length());
  output += dest_id_src.length();
  strncpy(output, "#", 1);
  output += 1;

  strncpy(output, channel_src.c_str(), channel_src.length());
  output += channel_src.length();
  strncpy(output, "#", 1);
  output += 1;

  strncpy(output, ts_src.c_str(), ts_src.length());
  output += ts_src.length();
  strncpy(output, "#", 1);
  output += 1;

  strncpy(output, message.name.c_str(), message.name.length());
  output += message.name.length();
  strncpy(output, "#", 1);
  output += 1;

  strncpy(output, message.message.c_str(), message.message.length());
  output += message.message.length();
  strncpy(output, "#", 1);
  output += 1;
  strncpy(output, "\0", 1);

  output -= 6 + src_id_src.length() + dest_id_src.length() + channel_src.length() + ts_src.length() + message.name.length() + message.message.length();

  // MSG("Serialized: %s", output);
  return output;
}

Protocol deserialize(char* input) {
  if (input == nullptr) {
    ERR("Null input, nothing to deserialize");
    throw SerializeException();
  }

  // MSG("Deserialize: %s", input);

  std::string wrap(input);
  int i1 = wrap.find_first_of('#');
  std::string src_id_str = wrap.substr(0, i1);
  // DBG("SID: %i %s", i1, src_id_str.c_str());
  int i2 = wrap.find_first_of('#', i1 + 1);
  std::string dest_id_str = wrap.substr(i1 + 1, i2 - i1 - 1);
  // DBG("DID: %i %s", i2, dest_id_str.c_str());
  int i2c = wrap.find_first_of('#', i2 + 1);
  std::string channel_str = wrap.substr(i2 + 1, i2c - i2 - 1);
  // DBG("CHANNEL: %i %s", i2c, channel_str.c_str());
  int i3 = wrap.find_first_of('#', i2c + 1);
  std::string ts_str = wrap.substr(i2c + 1, i3 - i2c - 1);
  // DBG("TS: %i %s", i3, ts_str.c_str());
  int i4 = wrap.find_first_of('#', i3 + 1);
  std::string name = wrap.substr(i3 + 1, i4 - i3 - 1);
  // DBG("NAME: %i %s", i4, name.c_str());
  int i5 = wrap.find_first_of('#', i4 + 1);
  std::string message = wrap.substr(i4 + 1, i5 - i4 - 1);
  // DBG("MSG: %i %s", i5, message.c_str());

  Protocol protocol;
  protocol.src_id = std::atoi(src_id_str.c_str());
  protocol.dest_id = std::atoi(dest_id_str.c_str());
  protocol.channel = std::atoi(channel_str.c_str());  // set channel value
  protocol.timestamp = std::stoll(ts_str.c_str());
  protocol.name = name;
  protocol.message = message;

  return protocol;
}

std::ostream& operator << (std::ostream& out, const Protocol& message) {
  out << "{\nsrc_id = " << message.src_id
      << "\t\ndest_id = " << message.dest_id
      << "\t\nchannel = " << message.channel
      << "\t\nt = " << message.timestamp
      << "\t\nname = " << message.name
      << "\t\nmessage = " << message.message
      << "\n}";
  return out;
}

