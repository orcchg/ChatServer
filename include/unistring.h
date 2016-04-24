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

#ifndef CHAT_SERVER_UNISTRING__H__
#define CHAT_SERVER_UNISTRING__H__

#include <exception>
#include <string>

#define __TO_STRING__(val) (std::to_string(val))

namespace db {

class WrappedString {
  typedef std::string::value_type Char_t;
  typedef std::string String_t;
  //WrappedString(const String_t& str);

public:
  WrappedString();
  WrappedString(const std::string& ordinary_str);
  WrappedString(const void* raw_char_data);
  virtual ~WrappedString();

  size_t length() const;
  int n_bytes() const;
  const Char_t* c_str() const;

  WrappedString& operator += (const WrappedString& rhs);

  static WrappedString to_string (int val);
  static WrappedString to_string (long val);
  static WrappedString to_string (long long val);
  static WrappedString to_string (unsigned val);
  static WrappedString to_string (unsigned long val);
  static WrappedString to_string (unsigned long long val);
  static WrappedString to_string (float val);
  static WrappedString to_string (double val);
  static WrappedString to_string (long double val);

private:
  String_t m_string;
};

/// @class WrappedStringException
/// @brief Represents a common exception raised by WrappedString class methods.
class WrappedStringException : public std::exception {
public:
  WrappedStringException(const char* message);
  virtual ~WrappedStringException() throw();

  const char* what() const throw();

private:
  const char* m_message;
};

}

#endif  // CHAT_SERVER_UNISTRING__H__

