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

#ifndef CHAT_SERVER_SYSTEM_TABLE__H__
#define CHAT_SERVER_SYSTEM_TABLE__H__

#include <string>
#include "database.h"

#define D_COLUMN_NAME_EXTRA_ID "ExtraID"
#define D_COLUMN_NAME_TIMESTAMP "Timestamp"
#define D_COLUMN_NAME_DATETIME "DateTime"
#define D_COLUMN_NAME_IP_ADDRESS "IpAddress"
#define D_COLUMN_NAME_PORT "Port"

namespace db {

class Record {
public:
  static Record EMPTY;

  Record(ID_t extra_id, uint64_t timestamp, const std::string& ip_address, int port);

  inline ID_t getExtraId() const { return m_extra_id; }
  inline uint64_t getTimestamp() const { return m_timestamp; }
  inline const std::string& getDateTime() const { return m_date_time; }
  inline const std::string& getIpAddress() const { return m_ip_address; }
  inline int getPort() const { return m_port; }

private:
  ID_t m_extra_id;
  uint64_t m_timestamp;
  std::string m_date_time;
  std::string m_ip_address;
  int m_port;
};

// ----------------------------------------------
class SystemTable : private Database {
public:
  SystemTable();
  SystemTable(SystemTable&& rval_obj);
  virtual ~SystemTable();

  ID_t addRecord(const Record& record);
  void removeRecord(ID_t id);
  Record getRecord(ID_t id);

private:
  void __init__() override;
  void __create_table__() override;

  SystemTable(const SystemTable& obj) = delete;
  SystemTable& operator = (const SystemTable& rhs) = delete;
  SystemTable& operator = (SystemTable&& rval_rhs) = delete;
};

}

#endif  // CHAT_SERVER_SYSTEM_TABLE__H__

