#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include "logger.h"
#include "my_parser.h"
#include <iostream>

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

/* Output */
// ----------------------------------------------------------------------------
std::ostream& operator << (std::ostream& out, const StartLine& startline) {
  out << "Start Line:\n\tMethod: " << startline.method << "\n\tPath: " << startline.path << "\n\tVersion: " << startline.version << std::endl;
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

/* Internals */
// ----------------------------------------------------------------------------
StartLine MyParser::parseStartLine(const std::string& start_line) const {
  reduce(start_line);
  StartLine startline;
  int i1 = start_line.find_first_of(" ");
  startline.method = start_line.substr(0, i1);
  int i2 = start_line.find_first_of("HTTP", i1 + 1);
  startline.path = start_line.substr(i1 + 1, i2 - i1 - 2);
  startline.version = std::atoi(start_line.substr(i2 + 7).c_str());
  return startline;
}

bool MyParser::isHeader(const std::string& header_line) const {
  int colon = header_line.find_first_of(':');
  return colon != std::string::npos;
}

Header MyParser::parseHeader(const std::string& header_line) const {
  reduce(header_line);
  int colon = header_line.find_first_of(':');
  Header header;
  header.name = header_line.substr(0, colon);
  header.value = header_line.substr(colon + 1);
  return header;
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

