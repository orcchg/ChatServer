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

#ifndef CHAT_SERVER_STRUCTURES__H__
#define CHAT_SERVER_STRUCTURES__H__

#include <ostream>
#include <string>
#include "api/types.h"

struct ConvertException {};

/* Internal implementation API */
// ----------------------------------------------------------------------------
/**
 * {
 *   "login":"Maxim",
 *   "password":"qwerty123"
 * }
 */
class LoginForm {
public:
  LoginForm(
    const std::string& login,
    const std::string& password);

  inline const std::string& getLogin() const { return m_login; }
  inline const std::string& getPassword() const { return m_password; }

  inline void setLogin(const std::string& login) { m_login = login; }
  inline void setPassword(const std::string& password) { m_password = password; }

  std::string toJson() const;
  static LoginForm fromJson(const std::string& json);

protected:
  std::string m_login;
  std::string m_password;
};

// ----------------------------------------------
/**
 * {
 *   "login":"Maxim",
 *   "email":"orcchg@yandex.ru",
 *   "password":"qwerty123"
 * }
 */
class RegistrationForm : public LoginForm {
public:
  RegistrationForm(
    const std::string& login,
    const std::string& email,
    const std::string& password);

  inline const std::string& getEmail() const { return m_email; }

  inline void setEmail(const std::string& email) { m_email = email; }

  std::string toJson() const;
  static RegistrationForm fromJson(const std::string& json);

protected:
  std::string m_email;
};

// ----------------------------------------------
/**
 * {
 *   "id":102993,
 *   "login":"Oleg",
 *   "channel":500,
 *   "dest_id":102997,
 *   "timestamp":1461516681500,
 *   "message":"Hello, World"
 * }
 */
class Message {
public:
  class Builder {
  public:
    Builder(ID_t id);
    Builder& setLogin(const std::string& login);
    Builder& setEmail(const std::string& email);
    Builder& setChannel(int channel);
    Builder& setDestId(ID_t dest_id);
    Builder& setTimestamp(uint64_t timestamp);
    Builder& setMessage(const std::string& message);
    Message build();

    inline ID_t getId() const { return m_id; }
    inline const std::string& getLogin() const { return m_login; }
    inline const std::string& getEmail() const { return m_email; }
    inline int getChannel() const { return m_channel; }
    inline ID_t getDestId() const { return m_dest_id; }
    inline uint64_t getTimestamp() const { return m_timestamp; }
    inline const std::string& getMessage() const { return m_message; }

  private:
    ID_t m_id;
    std::string m_login;
    std::string m_email;
    int m_channel;
    ID_t m_dest_id;
    uint64_t m_timestamp;
    std::string m_message; 
  };

  Message(const Builder& builder);
  std::string toJson() const;
  static Message fromJson(const std::string& json);

  inline ID_t getId() const { return m_id; }
  inline const std::string& getLogin() const { return m_login; }
  inline const std::string& getEmail() const { return m_email; }
  inline int getChannel() const { return m_channel; }
  inline ID_t getDestId() const { return m_dest_id; }
  inline uint64_t getTimestamp() const { return m_timestamp; }
  inline const std::string& getMessage() const { return m_message; }

private:
  ID_t m_id;
  std::string m_login;
  std::string m_email;
  int m_channel;
  ID_t m_dest_id;
  uint64_t m_timestamp;
  size_t m_size;
  std::string m_message;
};

// ----------------------------------------------
/**
 * {
 *   "id":102993,
 *   "login":"Oleg",
 *   "email":"oleg@ya.ru",
 *   "channel":500,
 * }
 */
class Peer {
public:
  class Builder {
  public:
    Builder(ID_t id);
    Builder& setLogin(const std::string& login);
    Builder& setEmail(const std::string& email);
    Builder& setChannel(int channel);
    Peer build();

    inline ID_t getId() const { return m_id; }
    inline const std::string& getLogin() const { return m_login; }
    inline const std::string& getEmail() const { return m_email; }
    inline int getChannel() const { return m_channel; }

  private:
    ID_t m_id;
    std::string m_login;
    std::string m_email;
    int m_channel;
  };

  Peer(const Builder& builder);
  std::string toJson() const;
  static Peer fromJson(const std::string& json);

  inline ID_t getId() const { return m_id; }
  inline const std::string& getLogin() const { return m_login; }
  inline const std::string& getEmail() const { return m_email; }
  inline int getChannel() const { return m_channel; }

private:
  ID_t m_id;
  std::string m_login;
  std::string m_email;
  int m_channel;
};

// ----------------------------------------------
class Token {
public:
  static Token EMPTY;

  explicit Token(const std::string& input);
  Token(const Token& token);
  virtual ~Token();

  const std::string& get() const;

private:
  std::string m_token;
};

std::ostream& operator << (std::ostream& out, const Token& token);

// ----------------------------------------------
#if SECURE

class PublicKey {
public:
  PublicKey(ID_t id, const std::string& key);
  std::string toJson() const;
  static PublicKey fromJson(const std::string& json);

private:
  ID_t m_id;
  std::string m_key;
};

#endif  // SECURE

#endif  // CHAT_SERVER_STRUCTURES__H__

