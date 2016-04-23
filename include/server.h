#ifndef CHAT_SERVER_SERVER__H__
#define CHAT_SERVER_SERVER__H__

#include <unordered_map>
#include "all.h"
#include "my_parser.h"
#include "peer.h"

class Server {
public:
  Server(int port_number);
  virtual ~Server();

  void run();
  void stop();

private:
  bool m_is_stopped;
  int m_socket;
  std::unordered_map<int, Peer> m_peers;
  MyParser m_parser;

  void runListener();
  void printClientInfo(sockaddr_in& peeraddr);
};

struct ServerException {};

#endif  // CHAT_SERVER_SERVER__H__

