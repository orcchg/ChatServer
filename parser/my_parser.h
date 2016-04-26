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

#ifndef MY_PARSER__H__
#define MY_PARSER__H__

#include <ostream>
#include <string>
#include <vector>

struct Query {
  std::string key;
  std::string value;
};

struct StartLine {
  std::string method;
  std::string path;
  int version;
};

struct CodeLine {
  int version;
  int code;
  std::string message;
};

struct Header {
  std::string name;
  std::string value;
};

struct Request {
  StartLine startline;
  std::vector<Header> headers;
  std::string body;

  static Request EMPTY;
};

struct Response {
  CodeLine codeline;
  std::vector<Header> headers;
  std::string body;

  static Response EMPTY;
};

std::ostream& operator << (std::ostream& out, const StartLine& startline);
std::ostream& operator << (std::ostream& out, const CodeLine& codeline);
std::ostream& operator << (std::ostream& out, const Header& header);
std::ostream& operator << (std::ostream& out, const Request& request);
std::ostream& operator << (std::ostream& out, const Response& response);

struct ParseException {};

class MyParser {
public:
  MyParser();
  virtual ~MyParser();

  Request parseRequest(char* http, int nbytes);
  Response parseResponse(char* http, int nbytes);

  std::string parsePath(const std::string& path, std::vector<Query>* params);

protected:
  StartLine parseStartLine(const std::string& start_line) const;
  CodeLine parseCodeLine(const std::string& code_line) const;
  bool isHeader(const std::string& header_line) const;
  Header parseHeader(const std::string& header_line) const;
};

std::string trim(const std::string& str, const std::string& whitespace = " \t");
std::string reduce(const std::string& str, const std::string& fill = " ", const std::string& whitespace = " \t");

#endif  // MY_PARSER__H__

