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

#include <cstring>
#include "api/api.h"
#include "client/utils.h"
#include "monkey.h"

namespace monkey {

Monkey::Monkey(const std::string& config_file, const std::string& suffix, int delay)
  : Client(config_file), m_delay(delay) {
  m_name.append(MONKEY_NAME).append("_").append(suffix);
  m_email.append(MONKEY_EMAIL).append("_").append(suffix);
  INF("Created monkey with name: %s and email: %s", m_name.c_str(), m_email.c_str());
}

Monkey::~Monkey() {
}

void Monkey::goToMainMenu() {
  if (checkRegistered(m_name)) {
    if (!checkLoggedIn(m_name)) {
      LoginForm form(m_name, MONKEY_PASSWORD);
      tryLogin(form);
    } else {
      ERR("Monkey has already logged in !");
      throw ClientException();
    }
  } else {
    RegistrationForm form(m_name, m_email, MONKEY_PASSWORD);
    tryRegister(form);
  }
}

void Monkey::startChat() {
  std::thread t(&Monkey::receiverThread, this);
  std::thread w(&Monkey::monkeyThread, this);
  t.detach();
  w.detach();

  printf("Type \'.m\' to list commands\n\n");

  std::ostringstream oss;
  std::string buffer;
  std::cin.ignore();
  while (!m_is_stopped && getline(std::cin, buffer)) {
    ID_t value = 0;
    std::string payload;
    util::Command command = util::parseCommand(buffer, value, &payload);
    switch (command) {
      case util::Command::LOGOUT:
        m_api_impl->logout(m_id);
        stopThread();
        continue;
      case util::Command::MENU:
        printf("\t\e[5;00;37m.q - logout\e[m\n");
        continue;
      default:  // skip
        break;
    }
  }
}

void Monkey::receiverThread() {
  // dispatch to Client::receiverThread()
  Client::receiverThread();
}

void Monkey::monkeyThread() {
  while (!m_is_stopped) {
    std::string buffer = "Hello, World!";

    // composing message
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    Message message = Message::Builder(m_id)
        .setLogin(m_name).setEmail(m_email).setChannel(m_channel).setDestId(m_dest_id)
        .setTimestamp(timestamp).setSize(buffer.length()).setEncrypted(false).setMessage(buffer).build();

    // sending message
    m_api_impl->sendMessage(message);
    std::this_thread::sleep_for(std::chrono::milliseconds(m_delay));
  }
  DBG("Monkey thread has stopped");
}

}  // namespace monkey

/* Main */
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
  // read configuration
  std::string config_file = "../client/local.cfg";
  if (argc >= 2) {
    char buffer[256];
    memset(buffer, 0, 256);
    strncpy(buffer, argv[1], strlen(argv[1]));
    config_file = std::string(buffer);
  }
  DBG("Configuration from file: %s", config_file.c_str());

  // start monkey
  monkey::Monkey monkey(config_file);
  monkey.init();
  monkey.run();
  return 0;
}

