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

#include <cstdio>
#include "api.h"

const char* ITEM_ADMIN    = D_ITEM_ADMIN;
const char* ITEM_KICK     = D_ITEM_KICK;
const char* ITEM_LOGIN    = D_ITEM_LOGIN;
const char* ITEM_EMAIL    = D_ITEM_EMAIL;
const char* ITEM_PASSWORD = D_ITEM_PASSWORD;

const char* ITEM_ID        = D_ITEM_ID;
const char* ITEM_SRC_ID    = D_ITEM_SRC_ID;
const char* ITEM_DEST_ID   = D_ITEM_DEST_ID;
const char* ITEM_CHANNEL   = D_ITEM_CHANNEL;
const char* ITEM_TIMESTAMP = D_ITEM_TIMESTAMP;
const char* ITEM_SIZE      = D_ITEM_SIZE;
const char* ITEM_ENCRYPTED = D_ITEM_ENCRYPTED;
const char* ITEM_MESSAGE   = D_ITEM_MESSAGE;

const char* ITEM_ACCEPT       = D_ITEM_ACCEPT;
const char* ITEM_ACTION       = D_ITEM_ACTION;
const char* ITEM_CHANNEL_PREV = D_ITEM_CHANNEL_PREV;
const char* ITEM_CHANNEL_NEXT = D_ITEM_CHANNEL_NEXT;
const char* ITEM_CHANNEL_MOVE = D_ITEM_CHANNEL_MOVE;
const char* ITEM_CHECK        = D_ITEM_CHECK;
const char* ITEM_CERT         = D_ITEM_CERT;
const char* ITEM_CODE         = D_ITEM_CODE;
const char* ITEM_KEY          = D_ITEM_KEY;
const char* ITEM_SYSTEM       = D_ITEM_SYSTEM;
const char* ITEM_TOKEN        = D_ITEM_TOKEN;
const char* ITEM_PAYLOAD      = D_ITEM_PAYLOAD;
const char* ITEM_PEERS        = D_ITEM_PEERS;

#if SECURE
const char* ITEM_PRIVATE_REQUEST = D_ITEM_PRIVATE_REQUEST;
const char* ITEM_PRIVATE_CONFIRM = D_ITEM_PRIVATE_CONFIRM;
const char* ITEM_PRIVATE_ABORT   = D_ITEM_PRIVATE_ABORT;
const char* ITEM_PRIVATE_PUBKEY  = D_ITEM_PRIVATE_PUBKEY;
const char* ITEM_PRIVATE_PUBKEY_EXCHANGE = D_ITEM_PRIVATE_PUBKEY_EXCHANGE;
#endif  // SECURE

const char* PATH_ADMIN          = D_PATH_ADMIN;
const char* PATH_KICK           = D_PATH_KICK;
const char* PATH_LOGIN          = D_PATH_LOGIN;
const char* PATH_REGISTER       = D_PATH_REGISTER;
const char* PATH_MESSAGE        = D_PATH_MESSAGE;
const char* PATH_LOGOUT         = D_PATH_LOGOUT;
const char* PATH_SWITCH_CHANNEL = D_PATH_SWITCH_CHANNEL;
const char* PATH_PEER_ID        = D_PATH_PEER_ID;
const char* PATH_IS_LOGGED_IN   = D_PATH_IS_LOGGED_IN;
const char* PATH_IS_REGISTERED  = D_PATH_IS_REGISTERED;
const char* PATH_CHECK_AUTH     = D_PATH_CHECK_AUTH;
const char* PATH_KICK_BY_AUTH   = D_PATH_KICK_BY_AUTH;
const char* PATH_ALL_PEERS      = D_PATH_ALL_PEERS;

#if SECURE
const char* PATH_PRIVATE_REQUEST = D_PATH_PRIVATE_REQUEST;
const char* PATH_PRIVATE_CONFIRM = D_PATH_PRIVATE_CONFIRM;
const char* PATH_PRIVATE_ABORT   = D_PATH_PRIVATE_ABORT;
const char* PATH_PRIVATE_PUBKEY  = D_PATH_PRIVATE_PUBKEY;
const char* PATH_PRIVATE_PUBKEY_EXCHANGE = D_PATH_PRIVATE_PUBKEY_EXCHANGE;
#endif  // SECURE

#if SECURE
std::string toString(HandshakeStatus status) {
  switch (status) {
    case HandshakeStatus::PENDING: return "PENDING";
    case HandshakeStatus::RESPONDED: return "RESPONDED";
    case HandshakeStatus::UNKNOWN:
    default:
      return "UNKNOWN";
  }
}

void print(HandshakeStatus status) {
  switch (status) {
    case HandshakeStatus::SENT:
      printf("\e[5;00;34mSENT\e[m");
      break;
    case HandshakeStatus::PENDING:
      printf("\e[5;00;36mPENDING\e[m");
      break;
    case HandshakeStatus::RESPONDED:
      printf("\e[5;00;32mRESPONDED\e[m");
      break;
    case HandshakeStatus::REJECTED:
      printf("\e[5;00;31mREJECTED\e[m");
      break;
    case HandshakeStatus::UNKNOWN:
    default:
      printf("\e[5;01;33mUNKNOWN\e[m");
      break;
  }
}
#endif  // SECURE

