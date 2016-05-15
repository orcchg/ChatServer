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

#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include "logger.h"
#include "my_parser.h"
#include <iostream>

Request Request::EMPTY;
Response Response::EMPTY;

MyParser::MyParser() {
}

MyParser::~MyParser() {
}

Request MyParser::parseRequest(char* http, int nbytes) {
  const char* CRLF = "\r\n";
  std::istringstream iss(http);
  //MSG("Input: %s", iss.str().c_str());
  Request request;

  // start line
  std::string start_line;
  std::getline(iss, start_line);
  //MSG("start=%s", start_line.c_str());
  request.startline = parseStartLine(start_line);

  // headers
  std::string header_line;
  std::vector<Header> headers;
  while (true) {
    std::getline(iss, header_line);
    if (isHeader(header_line)) {
      Header header = parseHeader(header_line);
      headers.push_back(header);
      //MSG("header=%s", header_line.c_str());
    } else {
      break;
    }
  }
  request.headers = headers;

  // body
  std::string ending = "";
  request.body = "";
  std::string line;
  while (std::getline(iss, line)) {
    line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
    request.body.append(ending);
    request.body.append(line);
    ending = "\n";
  }

  return request;  
}

Response MyParser::parseResponse(char* http, int nbytes) {
  const char* CRLF = "\r\n";
  std::istringstream iss(http);
  //MSG("Input: %s", iss.str().c_str());
  Response response;

  // code line
  std::string code_line;
  std::getline(iss, code_line);
  //MSG("code=%s", code_line.c_str());
  response.codeline = parseCodeLine(code_line);

  // headers
  std::string header_line;
  std::vector<Header> headers;
  while (true) {
    std::getline(iss, header_line);
    if (isHeader(header_line)) {
      Header header = parseHeader(header_line);
      headers.push_back(header);
      //MSG("header=%s", header_line.c_str());
    } else {
      break;
    }
  }
  response.headers = headers;

  // body
  std::string ending = "";
  response.body = "";
  std::string line;
  while (std::getline(iss, line)) {
    line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
    response.body.append(ending);
    response.body.append(line);
    ending = "\n";
  }

  return response;
}

std::string MyParser::parsePath(const std::string& path, std::vector<Query>* params) {
  int i1 = path.find_first_of("?");
  std::stringstream ss(path.substr(i1 + 1));
  std::string item;
  while (std::getline(ss, item, '&')) {
    int i2 = item.find_first_of('=');
    Query query;
    query.key = item.substr(0, i2);
    query.value = item.substr(i2 + 1);
    params->push_back(query);
  }
  return path.substr(0, i1);
}

/* Output */
// ----------------------------------------------------------------------------
std::ostream& operator << (std::ostream& out, const StartLine& startline) {
  out << "Start Line:\n\tMethod: " << startline.method << "\n\tPath: " << startline.path << "\n\tVersion: " << startline.version << std::endl;
  return out;
}

std::ostream& operator << (std::ostream& out, const CodeLine& codeline) {
  out << "Code Line:\n\tVersion: " << codeline.version << "\n\tCode: " << codeline.code << "\n\tMessage: " << codeline.message << std::endl;
  return out;
}

std::ostream& operator << (std::ostream& out, const Header& header) {
  out << "Header:\t" << header.name << ": " << header.value << std::endl;
  return out;
}

std::ostream& operator << (std::ostream& out, const Request& request) {
  out << "Request:\n" << request.startline;
  for (auto& it : request.headers) {
    out << it;
  }
  out << "Body:\n" << request.body << std::endl;
  return out;
}

std::ostream& operator << (std::ostream& out, const Response& response) {
  out << "Response:\n" << response.codeline;
  for (auto& it : response.headers) {
    out << it;
  }
  out << "Body:\n" << response.body << std::endl;
  return out;
}

/* To String */
// ----------------------------------------------------------------------------
std::string Query::to_string() const {
  std::ostringstream oss;
  oss << key << ":" << value;
  return oss.str();
}

std::string StartLine::to_string() const {
  std::ostringstream oss;
  oss << method << " " << path << " " << version;
  return oss.str();
}

std::string CodeLine::to_string() const {
  std::ostringstream oss;
  oss << version << " " << code << " " << message;
  return oss.str();
}

std::string Header::to_string() const {
  std::ostringstream oss;
  oss << name << ":" << value;
  return oss.str();
}

/* Internals */
// ----------------------------------------------------------------------------
StartLine MyParser::parseStartLine(const std::string& start_line) const {
  reduce(start_line);
  StartLine startline;
  int i1 = start_line.find_first_of(" ");
  startline.method = start_line.substr(0, i1);
  int i2 = start_line.find_first_of("HTTP", i1 + 1);
  if (i1 == std::string::npos || i2 == std::string::npos) {
    ERR("Parse error: invalid start line: %s", start_line.c_str());
    throw ParseException();
  }
  startline.path = start_line.substr(i1 + 1, i2 - i1 - 2);
  startline.version = std::atoi(start_line.substr(i2 + 7).c_str());
  return startline;
}

CodeLine MyParser::parseCodeLine(const std::string& code_line) const {
  reduce(code_line);
  CodeLine codeline;
  int i1 = code_line.find_first_of("HTTP");
  codeline.version = std::atoi(code_line.substr(i1 + 7, 1).c_str());
  int i2 = code_line.find_first_of(" ", i1 + 8);
  int i3 = code_line.find_first_of(" ", i2 + 1);
    if (i1 == std::string::npos || i2 == std::string::npos || i3 == std::string::npos) {
    ERR("Parse error: invalid code line: %s", code_line.c_str());
    throw ParseException();
  }
  codeline.code = std::atoi(code_line.substr(i2, i3 - i2).c_str());
  codeline.message = code_line.substr(i3 + 1);
  return codeline;
}

bool MyParser::isHeader(const std::string& header_line) const {
  int colon = header_line.find_first_of(':');
  return colon != std::string::npos;
}

Header MyParser::parseHeader(const std::string& header_line) const {
  reduce(header_line);
  int colon = header_line.find_first_of(':');
  if (colon == std::string::npos) {
    ERR("Parse error: invalid header: %s", header_line.c_str());
    throw ParseException();
  }
  Header header;
  header.name = header_line.substr(0, colon);
  header.value = header_line.substr(colon + 1);
  std::replace(header.value.begin(), header.value.end(), '\r', '\0');  // remove CR character
  std::replace(header.value.begin(), header.value.end(), '\n', '\0');  // remove LF character
  return header;
}

/* Check for emptiness */
// ----------------------------------------------------------------------------
bool Request::isEmpty() {
  return startline.version == 0 || startline.method.empty() || startline.path.empty();
}

bool Response::isEmpty() {
  return codeline.version == 0 || codeline.code == 0;
}

/* Trimming */
// ----------------------------------------------------------------------------
std::string trim(const std::string& str, const std::string& whitespace) {
  const auto strBegin = str.find_first_not_of(whitespace);
  if (strBegin == std::string::npos) {
    return ""; // no content
  }
  const auto strEnd = str.find_last_not_of(whitespace);
  const auto strRange = strEnd - strBegin + 1;
  return str.substr(strBegin, strRange);
}

std::string reduce(const std::string& str, const std::string& fill, const std::string& whitespace) {
  // trim first
  auto result = trim(str, whitespace);

  // replace sub ranges
  auto beginSpace = result.find_first_of(whitespace);
  while (beginSpace != std::string::npos) {
    const auto endSpace = result.find_first_not_of(whitespace, beginSpace);
    const auto range = endSpace - beginSpace;
    result.replace(beginSpace, range, fill);
    const auto newStart = beginSpace + fill.length();
    beginSpace = result.find_first_of(whitespace, newStart);
  }
  return result;
}

