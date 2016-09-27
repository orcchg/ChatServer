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

#include <string>
#include <vector>
#include <gtest/gtest.h>
#include "parser/my_parser.h"

namespace test {

/* Request */
// ----------------------------------------------
TEST(ParserTest, SingleRequest) {
  const char* http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}";

  MyParser parser;
  std::vector<Request> requests;
  Request request = parser.parseBufferedRequests((char*) http, 0, &requests);
  EXPECT_EQ(1, requests.size());

  const char* first_http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}";
  Request first = parser.parseRequest(first_http, 0);
  EXPECT_EQ(first, requests[0]);
  EXPECT_EQ(first, request);
}

TEST(ParserTest, BufferedRequest) {
  const char* http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}POST /message HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"id\":1000,\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"channel\":0,\"dest_id\":0,\"timestamp\":1472102149645,\"size\":5,\"encrypted\":0,\"message\":\"hello\"}DELETE /logout?id=1000 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";

  MyParser parser;
  std::vector<Request> requests;
  Request request = parser.parseBufferedRequests((char*) http, 0, &requests);
  EXPECT_EQ(3, requests.size());

  const char* first_http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}";
  Request first = parser.parseRequest(first_http, 0);
  EXPECT_EQ(first, requests[0]);
  EXPECT_EQ(first, request);

  const char* second_http = "POST /message HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"id\":1000,\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"channel\":0,\"dest_id\":0,\"timestamp\":1472102149645,\"size\":5,\"encrypted\":0,\"message\":\"hello\"}";
  Request second = parser.parseRequest(second_http, 0);
  EXPECT_EQ(second, requests[1]);

  const char* third_http = "DELETE /logout?id=1000 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";
  Request third = parser.parseRequest(third_http, 0);
  EXPECT_EQ(third, requests[2]);
}

TEST(ParserTest, BufferedRequest2) {
  const char* http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}DELETE /logout?id=1000 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\nPOST /message HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"id\":1000,\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"channel\":0,\"dest_id\":0,\"timestamp\":1472102149645,\"size\":5,\"encrypted\":0,\"message\":\"hello\"}";

  MyParser parser;
  std::vector<Request> requests;
  Request request = parser.parseBufferedRequests((char*) http, 0, &requests);
  EXPECT_EQ(3, requests.size());

  const char* first_http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}";
  Request first = parser.parseRequest(first_http, 0);
  EXPECT_EQ(first, requests[0]);
  EXPECT_EQ(first, request);

  const char* second_http = "DELETE /logout?id=1000 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";
  Request second = parser.parseRequest(second_http, 0);
  EXPECT_EQ(second, requests[1]);

  const char* third_http = "POST /message HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"id\":1000,\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"channel\":0,\"dest_id\":0,\"timestamp\":1472102149645,\"size\":5,\"encrypted\":0,\"message\":\"hello\"}";
  Request third = parser.parseRequest(third_http, 0);
  EXPECT_EQ(third, requests[2]);
}

TEST(ParserTest, BufferedRequest3) {
  const char* http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}DELETE /logout?id=1000 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\nPOST /message HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"id\":1000,\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"channel\":0,\"dest_id\":0,\"timestamp\":1472102149645,\"size\":5,\"encrypted\":0,\"message\":\"hello\"}GET /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\nPUT /switch_channel?id=1000&channel=500 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\nPOST /register HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}GET /register HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";

  MyParser parser;
  std::vector<Request> requests;
  Request request = parser.parseBufferedRequests((char*) http, 0, &requests);
  EXPECT_EQ(7, requests.size());

  const char* first_http = "POST /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}";
  Request first = parser.parseRequest(first_http, 0);
  EXPECT_EQ(first, requests[0]);
  EXPECT_EQ(first, request);

  const char* second_http = "DELETE /logout?id=1000 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";
  Request second = parser.parseRequest(second_http, 0);
  EXPECT_EQ(second, requests[1]);

  const char* third_http = "POST /message HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"id\":1000,\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"channel\":0,\"dest_id\":0,\"timestamp\":1472102149645,\"size\":5,\"encrypted\":0,\"message\":\"hello\"}";
  Request third = parser.parseRequest(third_http, 0);
  EXPECT_EQ(third, requests[2]);

  const char* fourth_http = "GET /login HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";
  Request fourth = parser.parseRequest(fourth_http, 0);
  EXPECT_EQ(fourth, requests[3]);

  const char* fifth_http = "PUT /switch_channel?id=1000&channel=500 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";
  Request fifth = parser.parseRequest(fifth_http, 0);
  EXPECT_EQ(fifth, requests[4]);

  const char* sixth_http = "POST /register HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n{\"login\":\"maxim\",\"email\":\"maxim@ya.ru\",\"password\":\"4d90851d4c4cf9b4b3b1823\",\"encrypted\":1}";
  Request sixth = parser.parseRequest(sixth_http, 0);
  EXPECT_EQ(sixth, requests[5]);

  const char* seventh_http = "GET /register HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n";
  Request seventh = parser.parseRequest(seventh_http, 0);
  EXPECT_EQ(seventh, requests[6]);
}

/* Response */
// ----------------------------------------------
TEST(ParserTest, SingleResponse) {
  const char* http = "HTTP/1.1 200 Logged Out\r\nServer: ChatServer-1.4-DEBUG\r\nContent-Type: application/json\r\nContent-Length: 103\r\n\r\n{\"system\":\"oleg has logged out\",\"action\":3,\"id\":1001,\"payload\":\"login=oleg&email=oleg@ya.ru&channel=0\"}";

  MyParser parser;
  std::vector<Response> responses;
  Response response = parser.parseBufferedResponses((char*) http, 0, &responses);
  EXPECT_EQ(1, responses.size());

  const char* first_http = "HTTP/1.1 200 Logged Out\r\nServer: ChatServer-1.4-DEBUG\r\nContent-Type: application/json\r\nContent-Length: 103\r\n\r\n{\"system\":\"oleg has logged out\",\"action\":3,\"id\":1001,\"payload\":\"login=oleg&email=oleg@ya.ru&channel=0\"}";
  Response first = parser.parseResponse(first_http, 0);
  EXPECT_EQ(first, responses[0]);
  EXPECT_EQ(first, response);
}

TEST(ParserTest, BufferedResponse) {
  const char* http = "HTTP/1.1 200 Logged Out\r\nServer: ChatServer-1.4-DEBUG\r\nContent-Type: application/json\r\nContent-Length: 103\r\n\r\n{\"system\":\"oleg has logged out\",\"action\":3,\"id\":1001,\"payload\":\"login=oleg&email=oleg@ya.ru&channel=0\"}HTTP/1.1 200 OK\r\nServer: ChatServer-1.4-DEBUG\r\nContent-Type: application/json\r\nContent-Length: 120\r\n\r\n{\"code\":0,\"action\":-2,\"id\":1000,\"token\":\"e7462a4f5295b5001cdb93eb3d6c65775910324ce38faacdf9e19403f4a3ca43\",\"payload\":\"\"}";

  MyParser parser;
  std::vector<Response> responses;
  Response response = parser.parseBufferedResponses((char*) http, 0, &responses);
  EXPECT_EQ(2, responses.size());

  const char* first_http = "HTTP/1.1 200 Logged Out\r\nServer: ChatServer-1.4-DEBUG\r\nContent-Type: application/json\r\nContent-Length: 103\r\n\r\n{\"system\":\"oleg has logged out\",\"action\":3,\"id\":1001,\"payload\":\"login=oleg&email=oleg@ya.ru&channel=0\"}";
  Response first = parser.parseResponse(first_http, 0);
  EXPECT_EQ(first, responses[0]);
  EXPECT_EQ(first, response);

  const char* second_http = "HTTP/1.1 200 OK\r\nServer: ChatServer-1.4-DEBUG\r\nContent-Type: application/json\r\nContent-Length: 120\r\n\r\n{\"code\":0,\"action\":-2,\"id\":1000,\"token\":\"e7462a4f5295b5001cdb93eb3d6c65775910324ce38faacdf9e19403f4a3ca43\",\"payload\":\"\"}";
  Response second = parser.parseResponse(second_http, 0);
  EXPECT_EQ(second, responses[1]);
}

}

