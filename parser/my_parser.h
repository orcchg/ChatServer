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

#ifndef MY_PARSER__H__
#define MY_PARSER__H__

#include <ostream>
#include <string>
#include <vector>
#include "exception.h"

struct FatPtr {
  int position;
  char* ptr;

  FatPtr() : position(-1), ptr(nullptr) {}
  FatPtr(int position, char* ptr) : position(position), ptr(ptr) {}

  inline bool operator <  (const FatPtr& rhs) const { return position <  rhs.position; }
  inline bool operator <= (const FatPtr& rhs) const { return position <= rhs.position; }
  inline bool operator >  (const FatPtr& rhs) const { return position >  rhs.position; }
  inline bool operator >= (const FatPtr& rhs) const { return position >= rhs.position; }
  inline bool operator == (const FatPtr& rhs) const { return position == rhs.position; }
  inline bool operator != (const FatPtr& rhs) const { return position != rhs.position; }
};

struct Query {
  std::string key;
  std::string value;

  std::string to_string() const;

  inline bool operator == (const Query& rhs) const {
    return key == rhs.key && value == rhs.value;
  }
  inline bool operator != (const Query& rhs) const {
    return !(*this == rhs);
  }
};

struct StartLine {
  std::string method;
  std::string path;
  int version;

  std::string to_string() const;

  inline bool operator == (const StartLine& rhs) const {
    return method == rhs.method && path == rhs.path && version == rhs.version;
  }
  inline bool operator != (const StartLine& rhs) const {
    return !(*this == rhs);
  }
};

struct CodeLine {
  int version;
  int code;
  std::string message;

  std::string to_string() const;

  inline bool operator == (const CodeLine& rhs) const {
    return version == rhs.version && code == rhs.code && message == rhs.message;
  }
  inline bool operator != (const CodeLine& rhs) const {
    return !(*this == rhs);
  }
};

struct Header {
  std::string name;
  std::string value;

  std::string to_string() const;

  inline bool operator == (const Header& rhs) const {
    return name == rhs.name && value == rhs.value;
  }
  inline bool operator != (const Header& rhs) const {
    return !(*this == rhs);
  }
};

struct Request {
  StartLine startline;
  std::vector<Header> headers;
  std::string body;

  static Request EMPTY;

  bool operator == (const Request& rhs) const;
  bool operator != (const Request& rhs) const;
};

struct Response {
  CodeLine codeline;
  std::vector<Header> headers;
  std::string body;

  static Response EMPTY;

  bool operator == (const Response& rhs) const;
  bool operator != (const Response& rhs) const;
};

std::ostream& operator << (std::ostream& out, const StartLine& startline);
std::ostream& operator << (std::ostream& out, const CodeLine& codeline);
std::ostream& operator << (std::ostream& out, const Header& header);
std::ostream& operator << (std::ostream& out, const Request& request);
std::ostream& operator << (std::ostream& out, const Response& response);

class MyParser {
public:
  MyParser();
  virtual ~MyParser();

  Request parseRequest(const char* http, int nbytes) const;
  Response parseResponse(const char* http, int nbytes) const;

  Request parseBufferedRequests(char* http, int nbytes, std::vector<Request>* requests) const;
  Response parseBufferedResponses(char* http, int nbytes, std::vector<Response>* responses) const;

  std::string parsePath(const std::string& path, std::vector<Query>* params) const;

  void parsePayload(const std::string& payload, std::vector<Query>* out) const;

protected:
  StartLine parseStartLine(const std::string& start_line) const;
  CodeLine parseCodeLine(const std::string& code_line) const;
  bool isHeader(const std::string& header_line) const;
  Header parseHeader(const std::string& header_line) const;
};

std::string trim(const std::string& str, const std::string& whitespace = " \t");
std::string reduce(const std::string& str, const std::string& fill = " ", const std::string& whitespace = " \t");
void parseParams(const std::string& input, std::vector<Query>* params);
Query parseQuery(const std::string& item);

#endif  // MY_PARSER__H__

