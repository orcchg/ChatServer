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

#if SECURE

#include "common.h"
#include "logger.h"
#include "keys_table_impl.h"

#define TABLE_NAME D_KEYS_TABLE_NAME

const char* COLUMN_NAME_SOURCE_ID = D_COLUMN_NAME_SOURCE_ID;
const char* COLUMN_NAME_KEY = D_COLUMN_NAME_KEY;

namespace db {

KeysTable::KeysTable()
  : Database(TABLE_NAME) {
  INF("enter KeysTable constructor.");
  this->__init__();
  INF("exit KeysTable constructor.");
}

KeysTable::KeysTable(KeysTable&& rval_obj)
  : Database(std::move(static_cast<Database&>(rval_obj))) {
}

KeysTable::~KeysTable() {
  INF("enter KeysTable destructor.");
  this->__close_database__();
  INF("exit KeysTable destructor.");
}

// ----------------------------------------------
void KeysTable::addKey(ID_t src_id, const KeyDTO& key) {
  INF("enter KeysTable::addKey().");
  std::string insert_statement = "INSERT OR REPLACE INTO '";
  insert_statement += this->m_table_name;
  insert_statement += "' ('" D_COLUMN_NAME_SOURCE_ID "', '" D_COLUMN_NAME_KEY "')";
  insert_statement += " VALUES(?1, ?2);";  // "' VALUES(?1, ?2, ?3);";
  this->__prepare_statement__(insert_statement);

  bool accumulate = true;
  ID_t id = this->m_next_id++;
  /*accumulate = accumulate && (sqlite3_bind_int64(this->m_db_statement, 1, id) == SQLITE_OK);
  DBG("ID [%lli] has been stored in table ["%s"], SQLite database ["%s"].",
      id, this->m_table_name.c_str(), this->m_db_name.c_str());*/

  accumulate = accumulate && (sqlite3_bind_int64(this->m_db_statement, 1/*2*/, src_id) == SQLITE_OK);
  DBG("SourceID [%lli] has been stored in table ["%s"], SQLite database ["%s"].",
      src_id, this->m_table_name.c_str(), this->m_db_name.c_str());

  WrappedString i_key = WrappedString(key.getKey());
  int key_n_bytes = i_key.n_bytes();
  accumulate = accumulate && (sqlite3_bind_text(this->m_db_statement, 2/*3*/, i_key.c_str(), key_n_bytes, SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Key ["%s"] has been stored in table ["%s"], SQLite database ["%s"].",
      i_key.c_str(), this->m_table_name.c_str(), this->m_db_name.c_str());

  sqlite3_step(this->m_db_statement);
  if (!accumulate) {
    ERR("Error during saving data into table ["%s"], database ["%s"] by statement ["%s"]!",
        this->m_table_name.c_str(), this->m_db_name.c_str(), insert_statement.c_str());
    this->__finalize_and_throw__(insert_statement.c_str(), SQLITE_ACCUMULATED_PREPARE_ERROR);
  } else {
    DBG("All insertions have succeeded.");
  }

  this->__finalize__(insert_statement.c_str());
  this->__increment_rows__();
  INF("exit KeysTable::addKey().");
}

// ----------------------------------------------
void KeysTable::removeKey(ID_t src_id) {
  INF("enter KeysTable::removeKey().");
  std::string delete_statement = "DELETE FROM '";
  delete_statement += this->m_table_name;
  delete_statement += "' WHERE " D_COLUMN_NAME_SOURCE_ID " == '";
  delete_statement += std::to_string(src_id);
  delete_statement += "';";
  this->__prepare_statement__(delete_statement);
  sqlite3_step(this->m_db_statement);
  ID_t id = sqlite3_column_int64(this->m_db_statement, 0);
  this->__finalize__(delete_statement.c_str());
  this->__decrement_rows__();
  if (id + 1 == this->m_next_id) {
    ID_t last_row_id = this->__read_last_id__(this->m_table_name);
    this->m_next_id = last_row_id + 1;
    DBG("Deleted key with largest ID. Next ID value is set to [%lli].", this->m_next_id);
  }
  if (this->__empty__()) {
    DBG("Table ["%s"] has become empty. Next ID value is set to zero.", this->m_table_name.c_str());
    this->m_next_id = BASE_ID;
  }
  DBG("Deleted key [ID: %lli] in table ["%s"].", id, this->m_table_name.c_str());
  INF("exit KeysTable::removeKey().");
}

// ----------------------------------------------
KeyDTO KeysTable::getKey(ID_t src_id) {
  INF("enter KeysTable::getKey().");
  std::string select_statement = "SELECT * FROM '";
  select_statement += this->m_table_name;
  select_statement += "' WHERE " D_COLUMN_NAME_SOURCE_ID " == '";
  select_statement += std::to_string(src_id);
  select_statement += "';";
  this->__prepare_statement__(select_statement);
  sqlite3_step(this->m_db_statement);
  ID_t check_id = sqlite3_column_int64(this->m_db_statement, 1);

  KeyDTO key = KeyDTO::EMPTY;
  if (check_id != UNKNOWN_ID && src_id == check_id) {
    DBG("Read src_id [%lli] from  table ["%s"] of database ["%s"].",
        check_id, this->m_table_name.c_str(), this->m_db_name.c_str());

    const void* raw_key = reinterpret_cast<const char*>(sqlite3_column_text(this->m_db_statement, 2));
    WrappedString key_str(raw_key);

    DBG("Loaded column data: " D_COLUMN_NAME_KEY " ["%s"].", key_str.c_str());
    key = KeyDTO(src_id, key_str.get());
    DBG("Proper key instance has been constructed.");
  } else {
    WRN("Key with src_id [%lli] is missing in table ["%s"] of database %p!",
        src_id, this->m_table_name.c_str(), this->m_db_handler);
  }

  this->__finalize__(select_statement.c_str());
  INF("exit KeysTable::getKey().");
  return (key);
}

void KeysTable::__init__() {
  DBG("enter KeysTable::__init__().");
  Database::__init__();
  ID_t last_row_id = this->__read_last_id__(this->m_table_name);
  this->m_next_id = last_row_id == 0 ? BASE_ID : last_row_id + 1;
  TRC("Initialization has completed: total rows [%i], last row id [%lli], next_id [%lli].",
      this->m_rows, last_row_id, this->m_next_id);
  DBG("exit KeysTable::__init__().");
}

void KeysTable::__create_table__() {
  DBG("enter KeysTable::__create_table__().");
  std::string statement = "CREATE TABLE IF NOT EXISTS ";
  statement += this->m_table_name;
  statement += "('ID' INTEGER PRIMARY KEY AUTOINCREMENT DEFAULT " STR_UNKNOWN_ID ", "
      "'" D_COLUMN_NAME_SOURCE_ID "' INTEGER UNIQUE DEFAULT " STR_UNKNOWN_ID ", "
      "'" D_COLUMN_NAME_KEY "' TEXT, "
      "FOREIGN KEY(" D_COLUMN_NAME_SOURCE_ID ") REFERENCES " D_PEERS_TABLE_NAME "(ID));";
  this->__prepare_statement__(statement);
  sqlite3_step(this->m_db_statement);
  DBG("Table ["%s"] has been successfully created.", this->m_table_name.c_str());
  this->__finalize__(statement.c_str());
  DBG("exit KeysTable::__create_table__().");
}

}

#endif  // SECURE

