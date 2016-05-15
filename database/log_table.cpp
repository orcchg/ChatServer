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

#include <chrono>
#include "logger.h"
#include "log_table.h"

#define TABLE_NAME "logs"
#define BASE_ID 1

namespace db {

const char* COLUMN_NAME_CONNECTION_ID = D_COLUMN_NAME_CONNECTION_ID;
const char* COLUMN_NAME_LAUNCH_TIMESTAMP = D_COLUMN_NAME_LAUNCH_TIMESTAMP;
const char* COLUMN_NAME_LOG_TIMESTAMP = D_COLUMN_NAME_LOG_TIMESTAMP;
const char* COLUMN_NAME_START_LINE = D_COLUMN_NAME_START_LINE;
const char* COLUMN_NAME_HEADERS = D_COLUMN_NAME_HEADERS;
const char* COLUMN_NAME_PAYLOAD = D_COLUMN_NAME_PAYLOAD;

LogRecord LogRecord::EMPTY = LogRecord(0, 0, 0, "", "", "");

LogRecord::LogRecord(
    ID_t connection_id,
    uint64_t launch_timestamp,
    uint64_t timestamp,
    const std::string& startline,
    const std::string& headers,
    const std::string& payload)
  : m_connection_id(connection_id)
  , m_launch_timestamp(launch_timestamp)
  , m_timestamp(timestamp)
  , m_startline(startline)
  , m_headers(headers)
  , m_payload(payload) {
}

LogTable::LogTable()
  : Database(TABLE_NAME) {
  INF("enter LogTable constructor.");
  this->__init__();
  INF("exit LogTable constructor.");
}

LogTable::LogTable(LogTable&& rval_obj)
  : Database(std::move(static_cast<Database&>(rval_obj))) {
}

LogTable::~LogTable() {
  INF("enter LogTable destructor.");
  this->__close_database__();
  INF("exit LogTable destructor.");
}

// ----------------------------------------------
ID_t LogTable::addLog(const LogRecord& log) {
  INF("enter LogTable::addLog().");
  std::string insert_statement = "INSERT INTO '";
  insert_statement += this->m_table_name;
  insert_statement += "' VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7);";
  this->__prepare_statement__(insert_statement);

  bool accumulate = true;
  ID_t log_id = this->m_next_id++;
  accumulate = accumulate &&
      (sqlite3_bind_int64(this->m_db_statement, 1, log_id) == SQLITE_OK);
  DBG("ID [%lli] has been stored in table ["%s"], SQLite database ["%s"].",
       log_id, this->m_table_name.c_str(), this->m_db_name.c_str());

  uint64_t i_launch_timestamp = log.getLaunchTimestamp();
  accumulate = accumulate &&
      (sqlite3_bind_int64(
          this->m_db_statement,
          2,
          i_launch_timestamp) == SQLITE_OK);
  DBG("Launch timestamp [%lu] has been stored in table ["%s"], SQLite database ["%s"].",
       i_launch_timestamp, this->m_table_name.c_str(), this->m_db_name.c_str());

  uint64_t i_timestamp = log.getTimestamp();
  accumulate = accumulate &&
      (sqlite3_bind_int64(
          this->m_db_statement,
          3,
          i_timestamp) == SQLITE_OK);
  DBG("Timestamp [%lu] has been stored in table ["%s"], SQLite database ["%s"].",
       i_timestamp, this->m_table_name.c_str(), this->m_db_name.c_str());

  WrappedString i_startline = WrappedString(log.getStartLine());
  int startline_n_bytes = i_startline.n_bytes();
  accumulate = accumulate &&
      (sqlite3_bind_text(
          this->m_db_statement,
          4,
          i_startline.c_str(),
          startline_n_bytes,
          SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Start Line ["%s"] has been stored in table ["%s"], "
       "SQLite database ["%s"].",
       i_startline.c_str(),
       this->m_table_name.c_str(),
       this->m_db_name.c_str());

  WrappedString i_headers = WrappedString(log.getHeaders());
  int headers_n_bytes = i_headers.n_bytes();
  accumulate = accumulate &&
      (sqlite3_bind_text(
          this->m_db_statement,
          5,
          i_headers.c_str(),
          headers_n_bytes,
          SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Headers ["%s"] has been stored in table ["%s"], "
       "SQLite database ["%s"].",
       i_headers.c_str(),
       this->m_table_name.c_str(),
       this->m_db_name.c_str());

  WrappedString i_payload = WrappedString(log.getPayload());
  int payload_n_bytes = i_payload.n_bytes();
  accumulate = accumulate &&
      (sqlite3_bind_text(
          this->m_db_statement,
          6,
          i_payload.c_str(),
          payload_n_bytes,
          SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Payload ["%s"] has been stored in table ["%s"], "
       "SQLite database ["%s"].",
       i_payload.c_str(),
       this->m_table_name.c_str(),
       this->m_db_name.c_str());

  sqlite3_step(this->m_db_statement);
  if (!accumulate) {
    ERR("Error during saving data into table ["%s"], database ["%s"] "
        "by statement ["%s"]!",
        this->m_table_name.c_str(),
        this->m_db_name.c_str(),
        insert_statement.c_str());
    this->__finalize_and_throw__(
        insert_statement.c_str(),
        SQLITE_ACCUMULATED_PREPARE_ERROR);
  } else {
    DBG("All insertions have succeeded.");
  }

  this->__finalize__(insert_statement.c_str());
  this->__increment_rows__();
  INF("exit LogTable::addLog().");
  return log_id;
}

// ----------------------------------------------
void LogTable::removeLog(ID_t id) {
  INF("enter LogTable::removeLog().");
  std::string delete_statement = "DELETE FROM '";
  delete_statement += this->m_table_name;
  delete_statement += "' WHERE ID == '";
  delete_statement += std::to_string(id);
  delete_statement += "';";
  this->__prepare_statement__(delete_statement);
  sqlite3_step(this->m_db_statement);
  this->__finalize__(delete_statement.c_str());
  this->__decrement_rows__();
  if (id + 1 == this->m_next_id) {
    ID_t last_row_id = this->__read_last_id__(this->m_table_name);
    this->m_next_id = last_row_id + 1;
    DBG("Deleted log with largest ID. Next ID value is set to [%lli].",
         this->m_next_id);
  }
  if (this->__empty__()) {
    DBG("Table ["%s"] has become empty. Next ID value is set to zero.",
         this->m_table_name.c_str());
    this->m_next_id = BASE_ID;
  }
  DBG("Deleted log [ID: %lli] in table ["%s"].",
       id, this->m_table_name.c_str());
  INF("exit LogTable::removeLog().");
}

// ----------------------------------------------
LogRecord LogTable::getLog(ID_t i_log_id) {
  INF("enter LogTable::getLog().");
  std::string select_statement = "SELECT * FROM '";
  select_statement += this->m_table_name;
  select_statement += "' WHERE ID == '";
  select_statement += std::to_string(i_log_id);
  select_statement += "';";

  this->__prepare_statement__(select_statement);
  sqlite3_step(this->m_db_statement);
  ID_t id = sqlite3_column_int64(this->m_db_statement, 0);
  DBG("Read id [%lli] from  table ["%s"] of database ["%s"], "
       "input id was [%lli].",
       id, this->m_table_name.c_str(), this->m_db_name.c_str(), i_log_id);
  TABLE_ASSERT("Input log id does not equal to primary key value "
               "from database!" &&
               id == i_log_id);

  LogRecord log = LogRecord::EMPTY;
  if (i_log_id != UNKNOWN_ID) {
    DBG("Read id [%lli] from  table ["%s"] of database ["%s"].",
         id, this->m_table_name.c_str(), this->m_db_name.c_str());

    ID_t connection_id = sqlite3_column_int64(this->m_db_statement, 1);
    uint64_t launch_timestamp = sqlite3_column_int64(this->m_db_statement, 2);
    uint64_t timestamp = sqlite3_column_int64(this->m_db_statement, 3);
    const void* raw_startline = reinterpret_cast<const char*>(
        sqlite3_column_text(this->m_db_statement, 4));
    WrappedString startline(raw_startline);
    const void* raw_headers = reinterpret_cast<const char*>(
        sqlite3_column_text(this->m_db_statement, 5));
    WrappedString headers(raw_headers);
    const void* raw_payload = reinterpret_cast<const char*>(
        sqlite3_column_text(this->m_db_statement, 6));
    WrappedString payload(raw_payload);

    DBG("Loaded column data: " COLUMN_NAME_CONNECTION_ID " [%lli]; " D_COLUMN_NAME_TIMESTAMP " [%lu]; " D_COLUMN_NAME_TIMESTAMP " [%lu]; " D_COLUMN_NAME_START_LINE " ["%s"]; " D_COLUMN_NAME_HEADERS " ["%s"]; " D_COLUMN_NAME_PAYLOAD " ["%s"].",
         connection_id,
         launch_timestamp,
         timestamp,
         startline.c_str(),
         headers.c_str(),
         payload.c_str());
    log = LogRecord(connection_id, launch_timestamp, timestamp, startline.get(), headers.get(), payload.get());
    DBG("Proper log instance has been constructed.");
  } else {
    WRN("ID [%lli] is missing in table ["%s"] of database %p!",
         i_log_id, this->m_table_name.c_str(), this->m_db_handler);
  }

  this->__finalize__(select_statement.c_str());
  INF("exit LogTable::getLog().");
  return (log);
}

/* Private members */
// ----------------------------------------------------------------------------
void LogTable::__init__() {
  DBG("enter LogTable::__init__().");
  Database::__init__();
  ID_t last_row_id = this->__read_last_id__(this->m_table_name);
  this->m_next_id = last_row_id == 0 ? BASE_ID : last_row_id + 1;
  TRC("Initialization has completed: total rows [%i], last row id [%lli], "
      "next_id [%lli].",
      this->m_rows, last_row_id, this->m_next_id);
  DBG("exit LogTable::__init__().");
}

void LogTable::__create_table__() {
  DBG("enter LogTable::__create_table__().");
  std::string statement = "CREATE TABLE IF NOT EXISTS ";
  statement += this->m_table_name;
  statement += "('ID' INTEGER PRIMARY KEY UNIQUE DEFAULT " STR_UNKNOWN_ID ", "
      "'" D_COLUMN_NAME_CONNECTION_ID "' INTEGER, "
      "'" D_COLUMN_NAME_LAUNCH_TIMESTAMP "' INTEGER, "
      "'" D_COLUMN_NAME_LOG_TIMESTAMP "' INTEGER, "
      "'" D_COLUMN_NAME_START_LINE "' TEXT, "
      "'" D_COLUMN_NAME_HEADERS "' TEXT, "
      "'" D_COLUMN_NAME_PAYLOAD "' TEXT);";
  this->__prepare_statement__(statement);
  sqlite3_step(this->m_db_statement);
  DBG("Table ["%s"] has been successfully created.",
       this->m_table_name.c_str());
  this->__finalize__(statement.c_str());
  DBG("exit LogTable::__create_table__().");
}

}

