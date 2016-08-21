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

#ifndef CHAT_SERVER_DATABASE__H__
#define CHAT_SERVER_DATABASE__H__

#include <string>
#include "sqlite/sqlite3.h"
#include "api/types.h"
#include "unistring.h"

#define SQLITE_ACCUMULATED_PREPARE_ERROR -1
#define TABLE_ASSERTION_ERROR_CODE -2

#define DATABASE_NAME "ChatServerDatabase.db"

typedef sqlite3* DB_Handler;
typedef sqlite3_stmt* DB_Statement;

#define EXPR_TO_STRING(x) #x
#define TABLE_ASSERT(expr)                                                    \
  ((expr)                                                                     \
   ? static_cast<void>(0)                                                     \
   : throw TableException(EXPR_TO_STRING(expr), TABLE_ASSERTION_ERROR_CODE))

namespace db {

class Database {
protected:
  Database(const std::string& table_name = "Default_Table");
  Database(Database&& rval_obj);
  virtual ~Database();

protected:
  std::string m_db_name;
  std::string m_table_name;
  DB_Handler m_db_handler;
  DB_Statement m_db_statement;
  ID_t m_next_id;
  int m_rows;

  static const int sql_statement_limit_length = 1000000;  // million

  virtual void __init__() = 0;
  virtual void __create_table__() = 0;

  void __open_database__();
  void __close_database__();
  int __prepare_statement__(const std::string& statement);
  int __prepare_statement__(const WrappedString& statement);
  bool __does_table_exist__();
  int __count__(const std::string& i_table_name);
  bool __empty__() const;  // soft invocation
  void __increment_rows__();  // soft invocation
  void __increase_rows__(int value);  // soft invocation
  void __decrement_rows__();  // soft invocation
  void __decrease_rows__(int value);  // soft invocation
  void __terminate__(const char* message);
  void __finalize__(const char* statement);
  void __finalize_and_throw__(const char* statement, int error_code);
  const std::string& __get_table_name__() const;  // soft invocation
  const char* __get_last_statement__() const;  // soft invocation
  void __set_last_statement__(const char* statement);  // soft invocation
  ID_t __read_last_id__(const std::string& table_name);
  void __drop_table__(const std::string& table_name);
  void __vacuum__();

#if ENABLED_ADVANCED_DEBUG
  void __where_check__(const ID_t& id);
  int __count_check__();
#endif

private:
  const char* m_last_statement;

  int __count_rows__(const std::string& i_table_name);
  bool __check_rows_init__() const;

  Database(const Database& obj) = delete;
  Database& operator = (const Database& rhs) = delete;
  Database& operator = (Database&& rval_rhs) = delete;
};


// ----------------------------------------------------------------------------
/// @class TableException
/// @brief Represents a common exception raised by Table class methods.
class TableException : public std::exception {
public:
  TableException(const char* message, int error_code);
  virtual ~TableException() throw();

  const char* what() const throw();
  int error() const throw();

private:
  const char* m_message;
  int m_error_code;
};

}

#endif  // CHAT_SERVER_DATABASE__H__

