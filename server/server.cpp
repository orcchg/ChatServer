#include <thread>
#include "my_parser.h"
#include "server.h"
#include "server_menu.h"

Server::Server(int port_number) {
  std::string port = std::to_string(port_number);

  // prepare address structure
  addrinfo hints;
  addrinfo* server_info;

  memset(&hints, 0, sizeof hints);  // make sure the struct is empty
  hints.ai_family = AF_INET;        // family of IP addresses
  hints.ai_socktype = SOCK_STREAM;  // TCP stream sockets
  hints.ai_flags = AI_PASSIVE;  // use local IP address to make server fully portable

  int status = getaddrinfo(nullptr, port.c_str(), &hints, &server_info);
  if (status != 0) {
    ERR("Failed to prepare address structure: %s", gai_strerror(status));  // see error message
    throw ServerException();
  }

  // get a socket
  m_socket = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);

  if (m_socket < 0) {
    ERR("Failed to open socket");
    throw ServerException();
  }

  // bind socket with address structure
  if (bind(m_socket, server_info->ai_addr, server_info->ai_addrlen) < 0) {
    ERR("Failed to bind socket to the address");
    throw ServerException();
  }

  freeaddrinfo(server_info);  // release address stucture and remove from linked list

  // when the socket of a type that promises reliable delivery still has untransmitted messages when it is closed
  linger linger_opt = { 1, 0 };  // timeout 0 seconds - close socket immediately
  setsockopt(m_socket, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));

  // listen for incoming connections
  listen(m_socket, 20);
}

Server::~Server() {
  // TODO: broadcast close signal to all peers
  close(m_socket);
}

void Server::run() {
  std::thread t(&Server::runListener, this);
  t.detach();

  menu::printHelp();

  // evaluate user commands
  char command[5];
  do {
    menu::printPrompt();
    scanf("%s", command);
  } while (menu::evaluate(this, command));
}

void Server::stop() {
  // TODO: stop server
}

/* Looper */
// ----------------------------------------------
void Server::runListener() {
  while (!m_is_stopped) {  // server loop
    sockaddr_in peer_address_structure;
    socklen_t peer_address_structure_size = sizeof(peer_address_structure);

    // accept one pending connection, waits until a new connection comes
    int peer_socket = accept(m_socket, reinterpret_cast<sockaddr*>(&peer_address_structure), &peer_address_structure_size);
    if (peer_socket < 0) {
      ERR("Failed to open new socket for data transfer");
      continue;  // skip failed connection
    }

    // get incoming message
    // TODO: get msg
  }
}

/* Utility */
// ----------------------------------------------
void Server::printClientInfo(sockaddr_in& peeraddr) {
  printf("Connection from IP %d.%d.%d.%d, port %d\n",
        (ntohl(peeraddr.sin_addr.s_addr) >> 24) & 0xff, // High byte of address
        (ntohl(peeraddr.sin_addr.s_addr) >> 16) & 0xff, // . . .
        (ntohl(peeraddr.sin_addr.s_addr) >> 8) & 0xff,  // . . .
        ntohl(peeraddr.sin_addr.s_addr) & 0xff,         // Low byte of addr
        ntohs(peeraddr.sin_port));
}

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  Server server(80);
  server.run();
  return 0;
}

