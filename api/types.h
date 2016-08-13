#ifndef CHAT_SERVER_TYPES__H__
#define CHAT_SERVER_TYPES__H__

#include "sqlite/sqlite3.h"

typedef sqlite3_int64 ID_t;

#define STR_UNKNOWN_ID "0"
static const int UNKNOWN_ID = 0;
static const int SERVER_ID  = 1;

static const int DEFAULT_CHANNEL = 0;
static const int WRONG_CHANNEL = -1;

#endif  // CHAT_SERVER_TYPES__H__

