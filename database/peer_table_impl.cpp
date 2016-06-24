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

#include "logger.h"
#include "peer_table_impl.h"

#define TABLE_NAME "peers"
#define BASE_ID 1000

namespace db {

const char* COLUMN_NAME_LOGIN = D_COLUMN_NAME_LOGIN;
const char* COLUMN_NAME_EMAIL = D_COLUMN_NAME_EMAIL;
const char* COLUMN_NAME_PASSWORD = D_COLUMN_NAME_PASSWORD;

PeerTable::PeerTable()
  : Database(TABLE_NAME) {
  INF("enter PeerTable constructor.");
  this->__init__();
  INF("exit PeerTable constructor.");
}

PeerTable::PeerTable(PeerTable&& rval_obj)
  : Database(std::move(static_cast<Database&>(rval_obj))) {
}

PeerTable::~PeerTable() {
  INF("enter PeerTable destructor.");
  this->__close_database__();
  INF("exit PeerTable destructor.");
}

// ----------------------------------------------
ID_t PeerTable::addPeer(const PeerDTO& peer) {
  INF("enter PeerTable::addPeer().");
  std::string insert_statement = "INSERT INTO '";
  insert_statement += this->m_table_name;
  insert_statement += "' VALUES(?1, ?2, ?3, ?4);";
  this->__prepare_statement__(insert_statement);

  bool accumulate = true;
  ID_t peer_id = this->m_next_id++;
  accumulate = accumulate && (sqlite3_bind_int64(this->m_db_statement, 1, peer_id) == SQLITE_OK);
  DBG("ID [%lli] has been stored in table ["%s"], SQLite database ["%s"].",
      peer_id, this->m_table_name.c_str(), this->m_db_name.c_str());

  WrappedString i_name = WrappedString(peer.getLogin());
  int login_n_bytes = i_name.n_bytes();
  accumulate = accumulate && (sqlite3_bind_text(this->m_db_statement, 2, i_name.c_str(), login_n_bytes, SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Login ["%s"] has been stored in table ["%s"], SQLite database ["%s"].",
      i_name.c_str(), this->m_table_name.c_str(), this->m_db_name.c_str());

  WrappedString i_email = WrappedString(peer.getEmail());
  int email_n_bytes = i_email.n_bytes();
  accumulate = accumulate && (sqlite3_bind_text(this->m_db_statement, 3, i_email.c_str(), email_n_bytes, SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Email ["%s"] has been stored in table ["%s"], SQLite database ["%s"].",
      i_email.c_str(), this->m_table_name.c_str(), this->m_db_name.c_str());

  WrappedString i_password = WrappedString(peer.getPassword());
  int password_n_bytes = i_password.n_bytes();
  accumulate = accumulate && (sqlite3_bind_text(this->m_db_statement, 4, i_password.c_str(), password_n_bytes, SQLITE_TRANSIENT) == SQLITE_OK);
  DBG("Password ["%s"] has been stored in table ["%s"], SQLite database ["%s"].",
      i_password.c_str(), this->m_table_name.c_str(), this->m_db_name.c_str());

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
  INF("exit PeerTable::addPeer().");
  return peer_id;
}

// ----------------------------------------------
void PeerTable::removePeer(ID_t id) {
  INF("enter PeerTable::removePeer().");
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
    DBG("Deleted peer with largest ID. Next ID value is set to [%lli].", this->m_next_id);
  }
  if (this->__empty__()) {
    DBG("Table ["%s"] has become empty. Next ID value is set to zero.", this->m_table_name.c_str());
    this->m_next_id = BASE_ID;
  }
  DBG("Deleted peer [ID: %lli] in table ["%s"].", id, this->m_table_name.c_str());
  INF("exit PeerTable::removePeer().");
}

// ----------------------------------------------
PeerDTO PeerTable::getPeerByLogin(const std::string& login, ID_t* id) {
  TRC("getPeerByLogin(%s)", login.c_str());
  return getPeerBySymbolic(COLUMN_NAME_LOGIN, login, id);
}

PeerDTO PeerTable::getPeerByEmail(const std::string& email, ID_t* id) {
  TRC("getPeerByEmail(%s)", email.c_str());
  return getPeerBySymbolic(COLUMN_NAME_EMAIL, email, id);
}

/* Private members */
// ----------------------------------------------------------------------------
PeerDTO PeerTable::getPeerBySymbolic(
    const char* symbolic,
    const std::string& value,
    ID_t* id) {
  INF("enter PeerTable::getPeerBySymbolic().");
  std::string select_statement = "SELECT * FROM '";
  select_statement += this->m_table_name;
  select_statement += "' WHERE ";
  select_statement += symbolic;
  select_statement += " LIKE '";
  select_statement += value;
  select_statement += "';";

  this->__prepare_statement__(select_statement);
  sqlite3_step(this->m_db_statement);
  *id = sqlite3_column_int64(this->m_db_statement, 0);

  PeerDTO peer = PeerDTO::EMPTY;
  if (*id != UNKNOWN_ID) {
    DBG("Read id [%lli] from  table ["%s"] of database ["%s"].",
        *id, this->m_table_name.c_str(), this->m_db_name.c_str());

    const void* raw_login = reinterpret_cast<const char*>(sqlite3_column_text(this->m_db_statement, 1));
    WrappedString login(raw_login);
    const void* raw_email = reinterpret_cast<const char*>(sqlite3_column_text(this->m_db_statement, 2));
    WrappedString email(raw_email);
    const void* raw_password = reinterpret_cast<const char*>(sqlite3_column_text(this->m_db_statement, 3));
    WrappedString password(raw_password);

    DBG("Loaded column data: " D_COLUMN_NAME_LOGIN " ["%s"]; " D_COLUMN_NAME_EMAIL " ["%s"]; " D_COLUMN_NAME_PASSWORD " ["%s"].",
        login.c_str(), email.c_str(), password.c_str());
    peer = PeerDTO(login.get(), email.get(), password.get());
    DBG("Proper peer instance has been constructed.");
  } else {
    WRN("Symbolic ["%s":"%s"] is missing in table ["%s"] of database %p!",
        symbolic, value.c_str(), this->m_table_name.c_str(), this->m_db_handler);
    *id = UNKNOWN_ID;
  }

  this->__finalize__(select_statement.c_str());
  INF("exit PeerTable::getPeerBySymbolic().");
  return (peer);
}

void PeerTable::__init__() {
  DBG("enter PeerTable::__init__().");
  Database::__init__();
  ID_t last_row_id = this->__read_last_id__(this->m_table_name);
  this->m_next_id = last_row_id == 0 ? BASE_ID : last_row_id + 1;
  TRC("Initialization has completed: total rows [%i], last row id [%lli], next_id [%lli].",
      this->m_rows, last_row_id, this->m_next_id);
  DBG("exit PeerTable::__init__().");
}

void PeerTable::__create_table__() {
  DBG("enter PeerTable::__create_table__().");
  std::string statement = "CREATE TABLE IF NOT EXISTS ";
  statement += this->m_table_name;
  statement += "('ID' INTEGER PRIMARY KEY UNIQUE DEFAULT " STR_UNKNOWN_ID ", "
      "'" D_COLUMN_NAME_LOGIN "' TEXT, "
      "'" D_COLUMN_NAME_EMAIL "' TEXT, "
      "'" D_COLUMN_NAME_PASSWORD "' TEXT);";
  this->__prepare_statement__(statement);
  sqlite3_step(this->m_db_statement);
  DBG("Table ["%s"] has been successfully created.", this->m_table_name.c_str());
  this->__finalize__(statement.c_str());
  DBG("exit PeerTable::__create_table__().");
}

}

