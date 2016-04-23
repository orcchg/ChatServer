#include "peer.h"

Peer::Peer(int id, const std::string& name)
  : m_id(id), m_name(name) {
}

void Peer::setSocket(int socket_id) {
  m_socket = socket_id;
}

