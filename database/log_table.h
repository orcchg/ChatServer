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

#ifndef CHAT_SERVER_LOG_TABLE__H__
#define CHAT_SERVER_LOG_TABLE__H__

#include <string>
#include "database.h"

#define D_COLUMN_NAME_CONNECTION_ID "ConnectionID"
#define D_COLUMN_NAME_LAUNCH_TIMESTAMP "LaunchTimestamp"
#define D_COLUMN_NAME_LOG_TIMESTAMP "Timestamp"
#define D_COLUMN_NAME_START_LINE "StartLine"
#define D_COLUMN_NAME_HEADERS "Headers"
#define D_COLUMN_NAME_PAYLOAD "Payload"

namespace db {

class LogRecord {
public:
  static LogRecord EMPTY;

  LogRecord(ID_t connection_id, uint64_t launch_timestamp, uint64_t timestamp, const std::string& startline, const std::string& headers, const std::string& payload);

  inline ID_t getConnectionId() const { return m_connection_id; }
  inline uint64_t getLaunchTimestamp() const { return m_launch_timestamp; }
  inline uint64_t getTimestamp() const { return m_timestamp; }
  inline const std::string& getStartLine() const { return m_startline; }
  inline const std::string& getHeaders() const { return m_headers; }
  inline const std::string& getPayload() const { return m_payload; }

private:
  ID_t m_connection_id;
  uint64_t m_launch_timestamp;
  uint64_t m_timestamp;
  std::string m_startline;
  std::string m_headers;
  std::string m_payload;
};

// ----------------------------------------------
class LogTable : private Database {
public:
  LogTable();
  LogTable(LogTable&& rval_obj);
  virtual ~LogTable();

  ID_t addLog(const LogRecord& log);
  void removeLog(ID_t id);
  LogRecord getLog(ID_t id);

private:
  void __init__() override;
  void __create_table__() override;

  LogTable(const LogTable& obj) = delete;
  LogTable& operator = (const LogTable& rhs) = delete;
  LogTable& operator = (LogTable&& rval_rhs) = delete;
};

}

#endif  // CHAT_SERVER_LOG_TABLE__H__

