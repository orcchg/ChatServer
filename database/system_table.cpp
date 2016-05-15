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
#include "system_table.h"

#define TABLE_NAME "records"
#define BASE_ID 1

namespace db {

const char* COLUMN_NAME_EXTRA_ID = D_COLUMN_NAME_EXTRA_ID;
const char* COLUMN_NAME_TIMESTAMP = D_COLUMN_NAME_TIMESTAMP;
const char* COLUMN_NAME_DATETIME = D_COLUMN_NAME_DATETIME;
const char* COLUMN_NAME_IP_ADDRESS = D_COLUMN_NAME_IP_ADDRESS;
const char* COLUMN_NAME_PORT = D_COLUMN_NAME_PORT;

Record Record::EMPTY = Record(0, 0, "", 0);

Record::Record(ID_t extra_id, uint64_t timestamp, const std::string& ip_address, int port)
  : m_extra_id(extra_id)
  , m_timestamp(timestamp)
  , m_date_time("")
  , m_ip_address(ip_address)
  , m_port(port) {

  std::time_t end_time = static_cast<time_t>(timestamp / 1000);
  m_date_time = std::string(std::ctime(&end_time));
  int i1 = m_date_time.find_last_of('\n');
  m_date_time = m_date_time.substr(0, i1);
}

SystemTable::SystemTable()
  : Database(TABLE_NAME) {
  INF("enter SystemTable constructor.");
  this->__init__();
  INF("exit SystemTable constructor.");
}

SystemTable::SystemTable(SystemTable&& rval_obj)
  : Database(std::move(static_cast<Database&>(rval_obj))) {
}

SystemTable::~SystemTable() {
  INF("enter SystemTable destructor.");
  this->__close_database__();
  INF("exit SystemTable destructor.");
}

// ----------------------------------------------
ID_t SystemTable::addRecord(const Record& record) {
  INF("enter SystemTable::addRecord().");
  std::string insert_statement = "INSERT INTO '";
  insert_statement += this->m_table_name;
  insert_statement += "' VALUES(?1, ?2, ?3, ?4, ?5, ?6);";
  this->__prepare_statement__(insert_statement);

  bool accumulate = true;
  ID_t record_id = this->m_next_id++;
  accumulate = accumulate &&
      (sqlite3_bind_int64(this->m_db_statement, 1, record_id) == SQLITE_OK);
  DBG("ID [%lli] has been stored in table ["%s"], SQLite database ["%s"].",
       record_id, this->m_table_name.c_str(), this->m_db_name.c_str());

  ID_t extra_id = record.getExtraId();
  accumulate = accumulate &&
      (sqlite3_bind_int64(this->m_db_statement, 2, extra_id) == SQLITE_OK);
  DBG("Extra ID [%lli] has been stored in table ["%s"], SQLite database ["%s"].",
       extra_id, this->m_table_name.c_str(), this->m_db_name.c_str());

  uint64_t i_timestamp = record.getTimestamp();
  accumulate = accumulate &&
      (sqlite3_bind_int64(
          this->m_db_statement,
          3,
          i_timestamp) == SQLITE_OK);
  DBG("Timestamp [%lu] has been stored in table ["%s"], SQLite database ["%s"].",
       i_timestamp, this->m_table_name.c_str(), this->m_db_name.c_str());

  WrappedString i_datetime = WrappedString(record.getDateTime());
  int datetime_n_bytes = i_datetime.n_bytes();
  accumulate = accumulate &&
      (sqlite3_bind_text(
          this->m_db_statement,
          4,
          i_datetime.c_str(),
          datetime_n_bytes,
          SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Date-Time ["%s"] has been stored in table ["%s"], "
       "SQLite database ["%s"].",
       i_datetime.c_str(),
       this->m_table_name.c_str(),
       this->m_db_name.c_str());

  WrappedString i_ipaddress = WrappedString(record.getIpAddress());
  int ipaddress_n_bytes = i_ipaddress.n_bytes();
  accumulate = accumulate &&
      (sqlite3_bind_text(
          this->m_db_statement,
          5,
          i_ipaddress.c_str(),
          ipaddress_n_bytes,
          SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("IP Address ["%s"] has been stored in table ["%s"], SQLite database ["%s"].",
       i_ipaddress.c_str(), this->m_table_name.c_str(), this->m_db_name.c_str());

  int i_port = record.getPort();
  accumulate = accumulate &&
      (sqlite3_bind_int(
          this->m_db_statement,
          6,
          i_port) == SQLITE_OK);
  DBG("Port [%i] has been stored in table ["%s"], SQLite database ["%s"].",
       i_port, this->m_table_name.c_str(), this->m_db_name.c_str());

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
  INF("exit SystemTable::addRecord().");
  return record_id;
}

// ----------------------------------------------
void SystemTable::removeRecord(ID_t id) {
  INF("enter SystemTable::removeRecord().");
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
    DBG("Deleted record with largest ID. Next ID value is set to [%lli].",
         this->m_next_id);
  }
  if (this->__empty__()) {
    DBG("Table ["%s"] has become empty. Next ID value is set to zero.",
         this->m_table_name.c_str());
    this->m_next_id = BASE_ID;
  }
  DBG("Deleted record [ID: %lli] in table ["%s"].",
       id, this->m_table_name.c_str());
  INF("exit SystemTable::removeRecord().");
}

// ----------------------------------------------
Record SystemTable::getRecord(ID_t i_record_id) {
  INF("enter SystemTable::getRecord().");
  std::string select_statement = "SELECT * FROM '";
  select_statement += this->m_table_name;
  select_statement += "' WHERE ID == '";
  select_statement += std::to_string(i_record_id);
  select_statement += "';";

  this->__prepare_statement__(select_statement);
  sqlite3_step(this->m_db_statement);
  ID_t id = sqlite3_column_int64(this->m_db_statement, 0);
  DBG("Read id [%lli] from  table ["%s"] of database ["%s"], "
       "input id was [%lli].",
       id, this->m_table_name.c_str(), this->m_db_name.c_str(), i_record_id);
  TABLE_ASSERT("Input record id does not equal to primary key value "
               "from database!" &&
               id == i_record_id);

  Record record = Record::EMPTY;
  if (i_record_id != UNKNOWN_ID) {
    DBG("Read id [%lli] from  table ["%s"] of database ["%s"].",
         id, this->m_table_name.c_str(), this->m_db_name.c_str());

    ID_t extra_id = sqlite3_column_int64(this->m_db_statement, 1);
    uint64_t timestamp = sqlite3_column_int64(this->m_db_statement, 2);
    const void* raw_datetime = reinterpret_cast<const char*>(
        sqlite3_column_text(this->m_db_statement, 3));
    WrappedString datetime(raw_datetime);
    const void* raw_ipaddress = reinterpret_cast<const char*>(
        sqlite3_column_text(this->m_db_statement, 4));
    WrappedString ipaddress(raw_ipaddress);
    int port = sqlite3_column_int(this->m_db_statement, 5);

    DBG("Loaded column data: " COLUMN_NAME_EXTRA_ID " [%lli]; " D_COLUMN_NAME_TIMESTAMP " [%lu]; " D_COLUMN_NAME_DATETIME " ["%s"]; " D_COLUMN_NAME_IP_ADDRESS " ["%s"]; " D_COLUMN_NAME_PORT " [%i].",
         extra_id,
         timestamp,
         datetime.c_str(),
         ipaddress.c_str(),
         port);
    record = Record(extra_id, timestamp, ipaddress.get(), port);
    DBG("Proper record instance has been constructed.");
  } else {
    WRN("ID [%lli] is missing in table ["%s"] of database %p!",
         i_record_id, this->m_table_name.c_str(), this->m_db_handler);
  }

  this->__finalize__(select_statement.c_str());
  INF("exit SystemTable::getRecord().");
  return (record);
}

/* Private members */
// ----------------------------------------------------------------------------
void SystemTable::__init__() {
  DBG("enter SystemTable::__init__().");
  Database::__init__();
  ID_t last_row_id = this->__read_last_id__(this->m_table_name);
  this->m_next_id = last_row_id == 0 ? BASE_ID : last_row_id + 1;
  TRC("Initialization has completed: total rows [%i], last row id [%lli], "
      "next_id [%lli].",
      this->m_rows, last_row_id, this->m_next_id);
  DBG("exit SystemTable::__init__().");
}

void SystemTable::__create_table__() {
  DBG("enter SystemTable::__create_table__().");
  std::string statement = "CREATE TABLE IF NOT EXISTS ";
  statement += this->m_table_name;
  statement += "('ID' INTEGER PRIMARY KEY UNIQUE DEFAULT " STR_UNKNOWN_ID ", "
      "'" D_COLUMN_NAME_EXTRA_ID "' INTEGER, "
      "'" D_COLUMN_NAME_TIMESTAMP "' INTEGER, "
      "'" D_COLUMN_NAME_DATETIME "' TEXT, "
      "'" D_COLUMN_NAME_IP_ADDRESS "' TEXT, "
      "'" D_COLUMN_NAME_PORT "' INTEGER);";
  this->__prepare_statement__(statement);
  sqlite3_step(this->m_db_statement);
  DBG("Table ["%s"] has been successfully created.",
       this->m_table_name.c_str());
  this->__finalize__(statement.c_str());
  DBG("exit SystemTable::__create_table__().");
}

}

