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

#ifndef CHAT_SERVER_MONKEY__H__
#define CHAT_SERVER_MONKEY__H__

#include "client/client.h"

#define MONKEY_DELAY 1000  // ms
#define MONKEY_MESSAGE "Hello, I'm a Monkey!"
#define MONKEY_NAME "monkey"
#define MONKEY_SUFFIX "0"
#define MONKEY_EMAIL "monkey@server.ru"
#define MONKEY_PASSWORD "showmethemoney"

namespace monkey {

class Monkey : public Client {
public:
  Monkey(
      const std::string& config_file,
      const std::string& message = MONKEY_MESSAGE,
      const std::string& suffix = MONKEY_SUFFIX,
      int delay = MONKEY_DELAY);
  virtual ~Monkey();

protected:
  int m_delay;
  std::string m_message;

  void goToMainMenu() override;

  void startChat() override;

  void receiverThread() override;
  void monkeyThread();
};

}  // namespace monkey

#endif  // CHAT_SERVER_MONKEY__H__

