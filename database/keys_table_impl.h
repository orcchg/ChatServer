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

#ifndef CHAT_SERVER_KEY_TABLE_IMPL__H__
#define CHAT_SERVER_KEY_TABLE_IMPL__H__

#if SECURE

#include "database.h"
#include "storage/key_dto.h"
#include "storage/keys_table.h"

#define D_COLUMN_NAME_SOURCE_ID "SourceID"
#define D_COLUMN_NAME_KEY "Key"

namespace db {

class KeysTable : private Database, public IKeysTable {
public:
  KeysTable();
  KeysTable(KeysTable&& rval_obj);
  virtual ~KeysTable();

  void addKey(ID_t src_id, const KeyDTO& key) override;
  void removeKey(ID_t src_id) override;
  KeyDTO getKey(ID_t src_id) override;

private:
  void __init__() override;
  void __create_table__() override;

  KeysTable(const KeysTable& obj) = delete;
  KeysTable& operator = (const KeysTable& rhs) = delete;
  KeysTable& operator = (KeysTable&& rval_rhs) = delete;
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_KEY_TABLE_IMPL__H__

