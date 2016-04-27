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

#include <cassert>
#include <cstring>
#include <cwchar>
#include "database.h"
#include "logger.h"

#define ROWS_IN_CASE_OF_NOT_EXISTING_TABLE -1
#define ID_IN_CASE_OF_NOT_EXISTING_TABLE -1

namespace db {

Database::Database(const std::string& i_table_name)
  : m_db_name(DATABASE_NAME)
  , m_table_name(i_table_name)
  , m_db_handler(nullptr)
  , m_db_statement(nullptr)
  , m_next_id(ID_IN_CASE_OF_NOT_EXISTING_TABLE)
  , m_rows(ROWS_IN_CASE_OF_NOT_EXISTING_TABLE)
  , m_last_statement("") {
}

Database::Database(Database&& rval_obj)
  : m_db_name(DATABASE_NAME)
  , m_table_name(rval_obj.m_table_name)
  , m_db_handler(rval_obj.m_db_handler)
  , m_db_statement(rval_obj.m_db_statement)
  , m_next_id(rval_obj.m_next_id)
  , m_rows(rval_obj.m_rows)
  , m_last_statement(rval_obj.m_last_statement) {
  rval_obj.m_db_name = "";
  rval_obj.m_table_name = "";
  rval_obj.m_db_handler = nullptr;
  rval_obj.m_db_statement = nullptr;
  rval_obj.m_next_id = ID_IN_CASE_OF_NOT_EXISTING_TABLE;
  rval_obj.m_rows = ROWS_IN_CASE_OF_NOT_EXISTING_TABLE;
  rval_obj.m_last_statement = "";
}

Database::~Database() {
  this->m_db_name = "";
  this->m_table_name = "";
  this->m_db_handler = nullptr;
  this->m_db_statement = nullptr;
  this->m_next_id = ID_IN_CASE_OF_NOT_EXISTING_TABLE;
  this->m_rows = ROWS_IN_CASE_OF_NOT_EXISTING_TABLE;
  this->m_last_statement = "";
}

void Database::__init__() {
  DBG("enter Database::__init__().");
  this->__open_database__();
  try {
    this->__create_table__();
    this->m_rows = this->__count__(this->m_table_name);
  } catch(TableException& e) {
    ERR(["%s"], e.what());
    this->__terminate__("Error during create table or counting rows!");
    // Do not allow invalid object of Table to be instantiated.
    WRN("throw from Database::__init__().");
    throw e;
  }
  DBG("exit Database::__init__().");
}

void Database::__open_database__() {
  DBG("enter Database::__open_database__().");
  int result = sqlite3_open(this->m_db_name.c_str(), &(this->m_db_handler));
  if (result != SQLITE_OK || !this->m_db_handler) {
    ERR("Unable to open database ["%s"]!", this->m_db_name.c_str());
    this->__terminate__("Error during open database.");
    WRN("throw from Database::__open_database__().");
    throw TableException("Unable to open database!", result);
  }
  DBG("SQLite database ["%s"] has been successfully opened and "
      "placed into %p.",
      this->m_db_name.c_str(), this->m_db_handler);
  sqlite3_limit(
      m_db_handler,
      SQLITE_LIMIT_SQL_LENGTH,
      Database::sql_statement_limit_length);
  DBG("SQL-statement max limit was set to %i in bytes.",
      Database::sql_statement_limit_length);
  DBG("exit Database::__open_database__().");
}

void Database::__close_database__() {
  DBG("enter Database::__close_database__().");
  if (this->m_db_statement) {
    DBG("Found prepared SQL statement at %p.", this->m_db_statement);
    this->__finalize__(this->m_last_statement);
  } else {
    DBG("Statement has been already finalized.");
  }
  if (this->m_db_handler) {
    DBG("Found valid database handler at %p.",
        this->m_db_handler);
    sqlite3_close(this->m_db_handler);
    this->m_db_handler = nullptr;
    DBG("Database ["%s"] has been successfully closed.",
        this->m_db_name.c_str());
  } else {
    DBG("Database ["%s"] has been already shut down.",
        this->m_db_name.c_str());
  }
  sqlite3_free(nullptr);
  DBG("exit Database::__close_database__().");
}

int Database::__prepare_statement__(const std::string& i_statement) {
  DBG("enter Database::__prepare_statement__().");
  int nByte = static_cast<int>(i_statement.length());
  TRC("Provided string SQL statement: ["%s"] of length %i.",
      i_statement.c_str(), nByte);
  TABLE_ASSERT("Invalid database handler! Database probably was not open." &&
               this->m_db_handler);
  int result = sqlite3_prepare_v2(
      this->m_db_handler,
      i_statement.c_str(),
      nByte,
      &(this->m_db_statement),
      nullptr);
  this->__set_last_statement__(i_statement.c_str());
  if (result != SQLITE_OK) {
    this->__finalize_and_throw__(i_statement.c_str(), result);
  }
  TRC("SQL statement has been compiled into byte-code and placed into %p.",
      this->m_db_statement);
  DBG("exit Database::__prepare_statement__().");
  return (result);
}

int Database::__prepare_statement__(const WrappedString& i_statement) {
  DBG("enter Database::__prepare_statement__().");
  int nByte = i_statement.n_bytes();
  TRC("Provided string SQL statement: ["%s"] of length %lli and bytes %i.",
      i_statement.c_str(),
      static_cast<long long int>(i_statement.length()),
      nByte);
  TABLE_ASSERT("Invalid database handler! Database probably was not open." &&
               this->m_db_handler);
  int result = sqlite3_prepare_v2(
      this->m_db_handler,
      i_statement.c_str(),
      nByte,
      &(this->m_db_statement),
      nullptr);
  this->__set_last_statement__(i_statement.c_str());
  if (result != SQLITE_OK) {
    this->__finalize_and_throw__(i_statement.c_str(), result);
  }
  TRC("SQL statement has been compiled into byte-code and placed into %p.",
      this->m_db_statement);
  DBG("exit Database::__prepare_statement__().");
  return (result);
}

bool Database::__does_table_exist__() {
  DBG("enter Database::__does_table_exist__().");
  std::string check_statement = "SELECT * FROM '";
  check_statement += this->m_table_name;
  check_statement += "';";
  int nByte = static_cast<int>(check_statement.length());
  TRC("Provided string SQL statement: ["%s"] of length %i.",
      check_statement.c_str(), nByte);
  TABLE_ASSERT("Invalid database handler! Database probably was not open." &&
               this->m_db_handler);
  int result = sqlite3_prepare_v2(
      this->m_db_handler,
      check_statement.c_str(),
      nByte,
      &(this->m_db_statement),
      nullptr);
  this->__set_last_statement__(check_statement.c_str());
  sqlite3_step(this->m_db_statement);
  this->__finalize__(check_statement.c_str());
  bool table_exists = false;
  switch (result) {
    case SQLITE_OK:
      DBG("SQLite table ["%s"] already exists.", this->m_table_name.c_str());
      table_exists = true;
      break;
    default:
      DBG("SQLite table ["%s"] does not exist.", this->m_table_name.c_str());
      break;
  }
  DBG("exit Database::__does_table_exist__().");
  return (table_exists);
}

int Database::__count__(const std::string& i_table_name) {
  DBG("enter Database::__count__().");
  if (this->m_rows <= ROWS_IN_CASE_OF_NOT_EXISTING_TABLE) {
    TRC("Rows count initialization has started.");
    this->m_rows = this->__count_rows__(i_table_name);
  }
  TRC("Number of rows in table ["%s"]: %i.",
      i_table_name.c_str(), this->m_rows);
  DBG("exit Database::__count__().");
  return (this->m_rows);
}

bool Database::__empty__() const {
  DBG("enter Database::__empty__().");
  this->__check_rows_init__();
  TRC("Number of rows in table ["%s"]: %i.",
      this->m_table_name.c_str(), this->m_rows);
  DBG("exit Database::__empty__().");
  return (this->m_rows == 0);
}

void Database::__increment_rows__() {
  DBG("enter Database::__increment_rows__().");
  this->__check_rows_init__();
  ++this->m_rows;
  DBG("exit Database::__increment_rows__().");
}

void Database::__increase_rows__(int value) {
  DBG("enter Database::__increase_rows__().");
  this->__check_rows_init__();
  this->m_rows += value;
  DBG("exit Database::__increase_rows__().");
}

void Database::__decrement_rows__() {
  DBG("enter Database::__decrement_rows__().");
  this->__check_rows_init__();
  if (this->m_rows > 0) {
    --this->m_rows;
  }
  DBG("exit Database::__decrement_rows__().");
}

void Database::__decrease_rows__(int value) {
  DBG("enter Database::__decrease_rows__().");
  this->__check_rows_init__();
  this->m_rows -= value;
  if (this->m_rows <= 0) {
    this->m_rows = 0;
  }
  DBG("exit Database::__decrease_rows__().");
}

void Database::__terminate__(const char* i_message) {
  DBG("enter Database::__terminate__().");
  WRN(["%s"], i_message);
  sqlite3_close(this->m_db_handler);
  this->m_db_handler = nullptr;
  this->m_last_statement = "";
  TRC("Database ["%s"] has been shut down.", this->m_db_name.c_str());
  sqlite3_free(nullptr);
  DBG("exit Database::__terminate__().");
}

void Database::__finalize__(const char* i_statement) {
  DBG("enter Database::__finalize__().");
  sqlite3_finalize(this->m_db_statement);
  this->m_db_statement = nullptr;
  this->m_last_statement = "";
  TRC("Statement ["%s"] (%i bytes) has been finalized.",
      i_statement, static_cast<int>(strlen(i_statement) * sizeof(char)));
  DBG("exit Database::__finalize__().");
}

void Database::__finalize_and_throw__(
    const char* i_statement,
    int i_error_code) {
  DBG("enter Database::__finalize_and_throw__().");
  ERR("Unable to prepare statement ["%s"] (%i bytes)!",
      i_statement, static_cast<int>(strlen(i_statement) * sizeof(char)));
  this->__finalize__(i_statement);
  DBG("exit Database::__finalize_and_throw__().");
  throw TableException("Unable to prepare statement!", i_error_code);
}

const std::string& Database::__get_table_name__() const {
  DBG("enter Database::__get_table_name__().");
  TRC("Table name is ["%s"].", this->m_table_name.c_str());
  DBG("exit Database::__get_table_name__().");
  return (this->m_table_name);
}

const char* Database::__get_last_statement__() const {
  DBG("enter Database::__get_last_statement__().");
  TRC("Got last recorded statement ["%s"].", this->m_last_statement);
  DBG("exit Database::__get_last_statement__().");
  return (this->m_last_statement);
}

void Database::__set_last_statement__(const char* i_statement) {
  DBG("enter Database::__set_last_statement__().");
  TRC("Set new last statement ["%s"].", i_statement);
  this->m_last_statement = i_statement;
  DBG("exit Database::__set_last_statement__().");
}

ID_t Database::__read_last_id__(const std::string& i_table_name) {
  DBG("enter Database::__read_last_id__().");
  std::string statement = "SELECT MAX(ID) FROM '" + i_table_name + "';";
  this->__prepare_statement__(statement);
  sqlite3_step(this->m_db_statement);
  ID_t last_id = sqlite3_column_int64(this->m_db_statement, 0);
  TRC("Read last id [%lli] from table ["%s"].", last_id, i_table_name.c_str());
  this->__finalize__(statement.c_str());
  DBG("exit Database::__read_last_id__().");
  return (last_id);
}

void Database::__drop_table__(const std::string& i_table_name) {
  DBG("enter Database::__drop_table__().");
  std::string drop_statement = "DROP TABLE IF EXISTS '";
  drop_statement += i_table_name;
  drop_statement += "';";
  this->__prepare_statement__(drop_statement);
  sqlite3_step(this->m_db_statement);
  this->__finalize__(drop_statement.c_str());
  DBG("Table with records ["%s"] has been dropped.",
      i_table_name.c_str());
  DBG("exit Database::__drop_table__().");
}

void Database::__vacuum__() {
  DBG("enter Database::__vacuum__().");
  std::string vacuum_statement = "VACUUM;";
  this->__prepare_statement__(vacuum_statement);
  sqlite3_step(this->m_db_statement);
  this->__finalize__(vacuum_statement.c_str());
  DBG("Shrank database at %p with name ["%s"] through VACUUM statement.",
      this->m_db_handler, this->m_db_name.c_str());
  DBG("exit Database::__vacuum__().");
}

#if ENABLED_ADVANCED_DEBUG
void Database::__where_check__(const ID_t& i_id) {
  MSG("Entrance into advanced debug source branch.");
  std::string where_statement = "SELECT EXISTS(SELECT * FROM '";
  where_statement += this->m_table_name;
  where_statement += "' WHERE ID == '";
  where_statement += std::to_string(i_id);
  where_statement += "');";
  this->__prepare_statement__(where_statement);
  sqlite3_step(this->m_db_statement);
  sqlite3_int64 answer = sqlite3_column_int64(this->m_db_statement, 0);
  if (answer) {
    INF1("ID [%lli] does exist in table ["%s"] of database %p.",
         i_id, this->m_table_name.c_str(), this->m_db_handler);
  } else {
    WRN1("ID [%lli] is MISSED in table ["%s"] of database %p!",
         i_id, this->m_table_name.c_str(), this->m_db_handler);
  }
  this->__finalize__(where_statement.c_str());
  MSG("Leave from advanced debug source branch.");
}

int Database::__count_check__() {
  MSG("Entrance into advanced debug source branch.");
  int rows = this->__count_rows__(this->m_table_name);
  INF1("Count of rows in table ["%s"] is equal to %i.",
       this->m_table_name.c_str(), rows);
  MSG("Leave from advanced debug source branch.");
  return (rows);
}
#endif


/* Private member-functions */
// ----------------------------------------------------------------------------
int Database::__count_rows__(const std::string& i_table_name) {
  DBG("enter Database::__count_rows__().");
  std::string count_statement = "SELECT COUNT(*) FROM \'";
  count_statement += i_table_name;
  count_statement += "\';";
  this->__prepare_statement__(count_statement);
  sqlite3_step(this->m_db_statement);
  int answer = sqlite3_column_int(this->m_db_statement, 0);
  this->__finalize__(count_statement.c_str());
  return (answer);
  DBG("exit Database::__count_rows__().");
}

bool Database::__check_rows_init__() const {
  DBG("enter Database::__check_rows_init__().");
  if (this->m_rows <= ROWS_IN_CASE_OF_NOT_EXISTING_TABLE) {
    ERR("Wrong initialization of database instance!");
    WRN("throw from Database::__check_rows_init__().");
    throw TableException(
        "Wrong initialization of database instance!",
        TABLE_ASSERTION_ERROR_CODE);
  }
  DBG("exit Database::__check_rows_init__().");
  return (true);
}


/* Table exception */
// ----------------------------------------------------------------------------
TableException::TableException(const char* i_message, int i_error_code)
  : m_message(i_message)
  , m_error_code(i_error_code) {
}

TableException::~TableException() throw() {
}

const char* TableException::what() const throw() {
  return (this->m_message);
}

int TableException::error() const throw() {
  return (this->m_error_code);
}

}

