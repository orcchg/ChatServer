#ifndef CHAT_SERVER_PROTOCOL__H__
#define CHAT_SERVER_PROTOCOL__H__

#include <ostream>
#include <string>

struct Protocol {
  int src_id;
  int dest_id;
  int channel;
  long long timestamp;
  std::string name;
  std::string message;

  bool operator == (const Protocol& rhs) const;
  bool operator != (const Protocol& rhs) const;
};

static Protocol EMPTY_MESSAGE;

struct SerializeException {};

char* serialize(const Protocol& message);
Protocol deserialize(char* input);

std::ostream& operator << (std::ostream& out, const Protocol& message);

#endif  // CHAT_SERVER_PROTOCOL__H__

