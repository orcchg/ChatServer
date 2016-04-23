#ifndef CHAT_SERVER_PEER__H__
#define CHAT_SERVER_PEER__H__

#include <string>

class Peer {
public:
  Peer(int id, const std::string& name);
  void setSocket(int socket_id);

private:
  int m_id;
  std::string m_name;
  int m_socket;
};

#endif  // CHAT_SERVER_PEER__H__

