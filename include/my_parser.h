#ifndef MY_PARSER__H__
#define MY_PARSER__H__

#include <ostream>
#include <string>
#include <vector>

struct StartLine {
  std::string method;
  std::string path;
  int version;
};

struct Header {
  std::string name;
  std::string value;
};

struct Request {
  StartLine startline;
  std::vector<Header> headers;
  std::string body;
};

std::ostream& operator << (std::ostream& out, const StartLine& startline);
std::ostream& operator << (std::ostream& out, const Header& header);
std::ostream& operator << (std::ostream& out, const Request& request);

class MyParser {
public:
  MyParser();
  virtual ~MyParser();

  Request parseRequest(char* http, int nbytes);

protected:
  StartLine parseStartLine(const std::string& start_line) const;
  bool isHeader(const std::string& header_line) const;
  Header parseHeader(const std::string& header_line) const;
};

std::string trim(const std::string& str, const std::string& whitespace = " \t");
std::string reduce(const std::string& str, const std::string& fill = " ", const std::string& whitespace = " \t");

#endif  // MY_PARSER__H__

