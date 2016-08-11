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
 */

#ifndef CHAT_SERVER_ICRYPTOR__H__
#define CHAT_SERVER_ICRYPTOR__H__

#if SECURE

#include <string>
#include "structures.h"

namespace secure {

class ICryptor {
public:
  virtual ~ICryptor() {}

  virtual std::string encrypt(const std::string& source) = 0;
  virtual std::string decrypt(const std::string& source) = 0;
};

class IAsymmetricCryptor {
public:
  virtual ~IAsymmetricCryptor() {}

  virtual std::string encrypt(const std::string& source, const Key& public_key, bool& encrypted) = 0;
  virtual std::string decrypt(const std::string& source, const Key& private_key, bool& decrypted) = 0;

  virtual int getEKlength() const = 0;
  virtual int getIVlength() const = 0;
  virtual void getEK(unsigned char* ek) const = 0;
  virtual void getIV(unsigned char* iv) const = 0;

  virtual void setEK(int ek_len, unsigned char* ek) = 0;
  virtual void setIV(int iv_len, unsigned char* iv) = 0;
};

}

#endif  // SECURE

#endif  // CHAT_SERVER_ICRYPTOR__H__

