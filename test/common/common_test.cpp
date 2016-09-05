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
#include <gtest/gtest.h>
#include "common.h"

namespace test {

TEST(CommonUtils, IsNumber) {
  std::string integer = "1000";
  ID_t id = UNKNOWN_ID;
  EXPECT_TRUE(common::isNumber(integer, id));
  EXPECT_EQ(1000, id);
}


TEST(CommonUtils, NotNumber) {
  std::string nan = "100z";
  ID_t id = UNKNOWN_ID;
  EXPECT_FALSE(common::isNumber(nan, id));
  EXPECT_EQ(100, id);
}

TEST(RestoreStrippedPEM, PublicInMemory1) {
  std::string pem_stripped = "-----BEGIN RSA PUBLIC KEY-----MIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASavjS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4eP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7xyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOGi11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB-----END RSA PUBLIC KEY-----";

  std::string pem_normal = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASav\njS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4\neP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7x\nyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOG\ni11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZ\nF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB\n-----END RSA PUBLIC KEY-----";

  std::string pem_restored = common::restoreStrippedInMemoryPEM(pem_stripped);
  EXPECT_STREQ(pem_normal.c_str(), pem_restored.c_str());
}

TEST(RestoreStrippedPEM, PublicInMemory2) {
  std::string pem_normal = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA5wz5fNXVx5FMs74hJPdHrZ1NnvD8o2I5EsHwY2Tmd4FqbkfiASav\njS5pglWYu10x0GHkJj1jHxU3yGqrnHchMW0zd0FmolVoc6Grutzryt0ekteCwsB4\neP23dfZhWRvUTCi0Mr94ui+8ejmTMT/db3Yg54fXK6ctPd5DnzojKm/h4n+z5r7x\nyRMQbQb8EUpn7cBqRGzD+kGadtEuiFwRQFyMOOWyhtQ0PpsyNNJTCNJsc8w3+gOG\ni11mfOYRZjaHINkUI4yJUincacUJOLQQK2jQH4mBH0P5Wq6b/mGcxz17yZDvnwZZ\nF3k82XDYsMYLEglKIzl1QXKua/dtEm0D+QIDAQAB\n-----END RSA PUBLIC KEY-----";

  std::string pem_stripped = common::preparse(pem_normal, common::PreparseLeniency::STRICT);
  std::string pem_restored = common::restoreStrippedInMemoryPEM(pem_stripped);
  EXPECT_STREQ(pem_normal.c_str(), pem_restored.c_str());
}

TEST(RestoreStrippedPEM, PublicFile1) {
  std::string public_pem = common::readFileToString("../test/data/public.pem");

  std::string pem_normal = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAx92l9nphMp3WWHxmn8CVoN5Z8osCbkVwFKtSHq8Wo4QiP2zRs0lH\n5ghDhid/ZqZBXFPM8ZxIXUWloQzD1AnI6Q60jHLAT1tWForKtIdUdzY+H1TM967H\nIAQXQCW+tatrRD2ZzeqQDHhed0NkQj0/LCgVVzaHEwazRGO+kHskAwFNcJvuynii\nkepTsnrH1CwxrFVGtzMiYMHV8obFUc2P8WszDAbjlv/1CcN7YpvyRAjq3LLePiGw\nzlXNkJP5+mOk3R5RnZDlxglS/5oNbFhD1Fu/dWX+nv0V+Cp9S6f1H22xMoy2I1+i\nK7X2JiCFNxtp8VgO1tMFPvLkq9xq5dOscwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

  EXPECT_STREQ(pem_normal.c_str(), public_pem.c_str());
}

TEST(RestoreStrippedPEM, PrivateInMemory1) {
  std::string pem_stripped = "-----BEGIN RSA PRIVATE KEY-----MIIEpQIBAAKCAQEAx92l9nphMp3WWHxmn8CVoN5Z8osCbkVwFKtSHq8Wo4QiP2zRs0lH5ghDhid/ZqZBXFPM8ZxIXUWloQzD1AnI6Q60jHLAT1tWForKtIdUdzY+H1TM967HIAQXQCW+tatrRD2ZzeqQDHhed0NkQj0/LCgVVzaHEwazRGO+kHskAwFNcJvuyniikepTsnrH1CwxrFVGtzMiYMHV8obFUc2P8WszDAbjlv/1CcN7YpvyRAjq3LLePiGwzlXNkJP5+mOk3R5RnZDlxglS/5oNbFhD1Fu/dWX+nv0V+Cp9S6f1H22xMoy2I1+iK7X2JiCFNxtp8VgO1tMFPvLkq9xq5dOscwIDAQABAoIBAQCuEl60gDvdcNi5sodTBdGMDXx7oRSZ5AJNDjV0ofvuqGuHoAg3xVBIidP9qLLuPUjZ1+a8W+guzDUIQmzgZTFFwlf/pwXVV/Bvq6wGdYNcXLLYaOwnoGKvgMCbTwR9h3HiOmCVloClS8TCzMAqbNtzYunLTqNwL7q8ir7zaTyhG9uWHD01E5hPkC+ngP/zfYaLJ+sbolW9Qj2fZzxW3rmHoiKy5AkkdTDHhp5poGrXFlIVUMhr3yFYLjoDh3e0vPNuTexUkv8s8GbBAQbhDjsf2no6IK3f5JtEB/91K6GmfBpef+iyZUU1pG6EXx9/Keh69Iq5sKoNgIbgmTLsa9qhAoGBAPATr3yypGDLwJDfmBzBRCvtoME8PRNMX81fN1ZwIqzxZ1tB6F276DzUuW1rDZmwLOsIFj+Quaas6NbIC0RFi8kvW40Pr86BKsrY2EQ/3Pu7O1a3S71qHGhAHHBxJGi/E4N/wSJVLWp6fB8DJqOdxuGW0AXC66lgSZuJ8+OguG3jAoGBANUfNewVgJZY5H5X8HiY6pZ0jWkyAq2U7rTYqaQuUOuJtNVeFLo6xj+Ne1+GnqWdRvUHGssaW7tSsgcfko7NcMdAu6pIhF+UxrDedswFeG7O0z+nFf1NCCHtYEIfDayPb+Ct2NWMxNowbCgx9ALOABhL1XrGuCxXYt+vTW4LIAwxAoGBAIc1rwn92pIhbsypARSAzJIo/PaXpJYv12zlCVeHRCA+vUUqM2JHKB7Kd7xmJHzAOiwMm+sk6Uoz69a7R40l1fpyz478nLkjCiTAR9z4Us77vgmypdeB4YndQacaMbVEmArhcraRXkivvyQANEzF2XLH61SzWOJFtm8BHPjAVd6dAoGBAJG3Qj4FwaKKasf7xn4eR57RV/KJ8AzQ3Jkn3m1UAZ3ZzJtqNQ/TqcLAMI9y0rv3mhFkZyxg/EFK3FBEhQdAbhC+MNHPvTpA1c0Offkm8F4K6aMG0eEbryjLTVpIMyg99kePdcck9V8dZoXhCa51PNlf2DmW70vZ/89i47UOxD2xAoGARoqgA9BMIlwfBcQ/7kBw6HbmadzV+Ob+rzoZjJiuSIQly9mv0rIQgIGTFPcmPrZtb7FEGb4r101fLZwPNljIb430yaqz5fzGc3Wjv+Htjot9pSYFrlwr/C1/LCG0HfFj4srJSrGxPeMsohx3dhKj0Gr7o8fXi0d5ALhC/0g8Idk=-----END RSA PRIVATE KEY-----";

  std::string pem_normal = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAx92l9nphMp3WWHxmn8CVoN5Z8osCbkVwFKtSHq8Wo4QiP2zR\ns0lH5ghDhid/ZqZBXFPM8ZxIXUWloQzD1AnI6Q60jHLAT1tWForKtIdUdzY+H1TM\n967HIAQXQCW+tatrRD2ZzeqQDHhed0NkQj0/LCgVVzaHEwazRGO+kHskAwFNcJvu\nyniikepTsnrH1CwxrFVGtzMiYMHV8obFUc2P8WszDAbjlv/1CcN7YpvyRAjq3LLe\nPiGwzlXNkJP5+mOk3R5RnZDlxglS/5oNbFhD1Fu/dWX+nv0V+Cp9S6f1H22xMoy2\nI1+iK7X2JiCFNxtp8VgO1tMFPvLkq9xq5dOscwIDAQABAoIBAQCuEl60gDvdcNi5\nsodTBdGMDXx7oRSZ5AJNDjV0ofvuqGuHoAg3xVBIidP9qLLuPUjZ1+a8W+guzDUI\nQmzgZTFFwlf/pwXVV/Bvq6wGdYNcXLLYaOwnoGKvgMCbTwR9h3HiOmCVloClS8TC\nzMAqbNtzYunLTqNwL7q8ir7zaTyhG9uWHD01E5hPkC+ngP/zfYaLJ+sbolW9Qj2f\nZzxW3rmHoiKy5AkkdTDHhp5poGrXFlIVUMhr3yFYLjoDh3e0vPNuTexUkv8s8GbB\nAQbhDjsf2no6IK3f5JtEB/91K6GmfBpef+iyZUU1pG6EXx9/Keh69Iq5sKoNgIbg\nmTLsa9qhAoGBAPATr3yypGDLwJDfmBzBRCvtoME8PRNMX81fN1ZwIqzxZ1tB6F27\n6DzUuW1rDZmwLOsIFj+Quaas6NbIC0RFi8kvW40Pr86BKsrY2EQ/3Pu7O1a3S71q\nHGhAHHBxJGi/E4N/wSJVLWp6fB8DJqOdxuGW0AXC66lgSZuJ8+OguG3jAoGBANUf\nNewVgJZY5H5X8HiY6pZ0jWkyAq2U7rTYqaQuUOuJtNVeFLo6xj+Ne1+GnqWdRvUH\nGssaW7tSsgcfko7NcMdAu6pIhF+UxrDedswFeG7O0z+nFf1NCCHtYEIfDayPb+Ct\n2NWMxNowbCgx9ALOABhL1XrGuCxXYt+vTW4LIAwxAoGBAIc1rwn92pIhbsypARSA\nzJIo/PaXpJYv12zlCVeHRCA+vUUqM2JHKB7Kd7xmJHzAOiwMm+sk6Uoz69a7R40l\n1fpyz478nLkjCiTAR9z4Us77vgmypdeB4YndQacaMbVEmArhcraRXkivvyQANEzF\n2XLH61SzWOJFtm8BHPjAVd6dAoGBAJG3Qj4FwaKKasf7xn4eR57RV/KJ8AzQ3Jkn\n3m1UAZ3ZzJtqNQ/TqcLAMI9y0rv3mhFkZyxg/EFK3FBEhQdAbhC+MNHPvTpA1c0O\nffkm8F4K6aMG0eEbryjLTVpIMyg99kePdcck9V8dZoXhCa51PNlf2DmW70vZ/89i\n47UOxD2xAoGARoqgA9BMIlwfBcQ/7kBw6HbmadzV+Ob+rzoZjJiuSIQly9mv0rIQ\ngIGTFPcmPrZtb7FEGb4r101fLZwPNljIb430yaqz5fzGc3Wjv+Htjot9pSYFrlwr\n/C1/LCG0HfFj4srJSrGxPeMsohx3dhKj0Gr7o8fXi0d5ALhC/0g8Idk=\n-----END RSA PRIVATE KEY-----";

  std::string pem_restored = common::restoreStrippedInMemoryPEM(pem_stripped);
  EXPECT_STREQ(pem_normal.c_str(), pem_restored.c_str());
}

TEST(RestoreStrippedPEM, PrivateInMemory2) {
  std::string pem_normal = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAx92l9nphMp3WWHxmn8CVoN5Z8osCbkVwFKtSHq8Wo4QiP2zR\ns0lH5ghDhid/ZqZBXFPM8ZxIXUWloQzD1AnI6Q60jHLAT1tWForKtIdUdzY+H1TM\n967HIAQXQCW+tatrRD2ZzeqQDHhed0NkQj0/LCgVVzaHEwazRGO+kHskAwFNcJvu\nyniikepTsnrH1CwxrFVGtzMiYMHV8obFUc2P8WszDAbjlv/1CcN7YpvyRAjq3LLe\nPiGwzlXNkJP5+mOk3R5RnZDlxglS/5oNbFhD1Fu/dWX+nv0V+Cp9S6f1H22xMoy2\nI1+iK7X2JiCFNxtp8VgO1tMFPvLkq9xq5dOscwIDAQABAoIBAQCuEl60gDvdcNi5\nsodTBdGMDXx7oRSZ5AJNDjV0ofvuqGuHoAg3xVBIidP9qLLuPUjZ1+a8W+guzDUI\nQmzgZTFFwlf/pwXVV/Bvq6wGdYNcXLLYaOwnoGKvgMCbTwR9h3HiOmCVloClS8TC\nzMAqbNtzYunLTqNwL7q8ir7zaTyhG9uWHD01E5hPkC+ngP/zfYaLJ+sbolW9Qj2f\nZzxW3rmHoiKy5AkkdTDHhp5poGrXFlIVUMhr3yFYLjoDh3e0vPNuTexUkv8s8GbB\nAQbhDjsf2no6IK3f5JtEB/91K6GmfBpef+iyZUU1pG6EXx9/Keh69Iq5sKoNgIbg\nmTLsa9qhAoGBAPATr3yypGDLwJDfmBzBRCvtoME8PRNMX81fN1ZwIqzxZ1tB6F27\n6DzUuW1rDZmwLOsIFj+Quaas6NbIC0RFi8kvW40Pr86BKsrY2EQ/3Pu7O1a3S71q\nHGhAHHBxJGi/E4N/wSJVLWp6fB8DJqOdxuGW0AXC66lgSZuJ8+OguG3jAoGBANUf\nNewVgJZY5H5X8HiY6pZ0jWkyAq2U7rTYqaQuUOuJtNVeFLo6xj+Ne1+GnqWdRvUH\nGssaW7tSsgcfko7NcMdAu6pIhF+UxrDedswFeG7O0z+nFf1NCCHtYEIfDayPb+Ct\n2NWMxNowbCgx9ALOABhL1XrGuCxXYt+vTW4LIAwxAoGBAIc1rwn92pIhbsypARSA\nzJIo/PaXpJYv12zlCVeHRCA+vUUqM2JHKB7Kd7xmJHzAOiwMm+sk6Uoz69a7R40l\n1fpyz478nLkjCiTAR9z4Us77vgmypdeB4YndQacaMbVEmArhcraRXkivvyQANEzF\n2XLH61SzWOJFtm8BHPjAVd6dAoGBAJG3Qj4FwaKKasf7xn4eR57RV/KJ8AzQ3Jkn\n3m1UAZ3ZzJtqNQ/TqcLAMI9y0rv3mhFkZyxg/EFK3FBEhQdAbhC+MNHPvTpA1c0O\nffkm8F4K6aMG0eEbryjLTVpIMyg99kePdcck9V8dZoXhCa51PNlf2DmW70vZ/89i\n47UOxD2xAoGARoqgA9BMIlwfBcQ/7kBw6HbmadzV+Ob+rzoZjJiuSIQly9mv0rIQ\ngIGTFPcmPrZtb7FEGb4r101fLZwPNljIb430yaqz5fzGc3Wjv+Htjot9pSYFrlwr\n/C1/LCG0HfFj4srJSrGxPeMsohx3dhKj0Gr7o8fXi0d5ALhC/0g8Idk=\n-----END RSA PRIVATE KEY-----";

  std::string pem_stripped = common::preparse(pem_normal, common::PreparseLeniency::STRICT);
  std::string pem_restored = common::restoreStrippedInMemoryPEM(pem_stripped);
  EXPECT_STREQ(pem_normal.c_str(), pem_restored.c_str());
}

TEST(RestoreStrippedPEM, PrivateFile1) {
  std::string private_pem = common::readFileToString("../test/data/private.pem");

  std::string pem_normal = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAx92l9nphMp3WWHxmn8CVoN5Z8osCbkVwFKtSHq8Wo4QiP2zR\ns0lH5ghDhid/ZqZBXFPM8ZxIXUWloQzD1AnI6Q60jHLAT1tWForKtIdUdzY+H1TM\n967HIAQXQCW+tatrRD2ZzeqQDHhed0NkQj0/LCgVVzaHEwazRGO+kHskAwFNcJvu\nyniikepTsnrH1CwxrFVGtzMiYMHV8obFUc2P8WszDAbjlv/1CcN7YpvyRAjq3LLe\nPiGwzlXNkJP5+mOk3R5RnZDlxglS/5oNbFhD1Fu/dWX+nv0V+Cp9S6f1H22xMoy2\nI1+iK7X2JiCFNxtp8VgO1tMFPvLkq9xq5dOscwIDAQABAoIBAQCuEl60gDvdcNi5\nsodTBdGMDXx7oRSZ5AJNDjV0ofvuqGuHoAg3xVBIidP9qLLuPUjZ1+a8W+guzDUI\nQmzgZTFFwlf/pwXVV/Bvq6wGdYNcXLLYaOwnoGKvgMCbTwR9h3HiOmCVloClS8TC\nzMAqbNtzYunLTqNwL7q8ir7zaTyhG9uWHD01E5hPkC+ngP/zfYaLJ+sbolW9Qj2f\nZzxW3rmHoiKy5AkkdTDHhp5poGrXFlIVUMhr3yFYLjoDh3e0vPNuTexUkv8s8GbB\nAQbhDjsf2no6IK3f5JtEB/91K6GmfBpef+iyZUU1pG6EXx9/Keh69Iq5sKoNgIbg\nmTLsa9qhAoGBAPATr3yypGDLwJDfmBzBRCvtoME8PRNMX81fN1ZwIqzxZ1tB6F27\n6DzUuW1rDZmwLOsIFj+Quaas6NbIC0RFi8kvW40Pr86BKsrY2EQ/3Pu7O1a3S71q\nHGhAHHBxJGi/E4N/wSJVLWp6fB8DJqOdxuGW0AXC66lgSZuJ8+OguG3jAoGBANUf\nNewVgJZY5H5X8HiY6pZ0jWkyAq2U7rTYqaQuUOuJtNVeFLo6xj+Ne1+GnqWdRvUH\nGssaW7tSsgcfko7NcMdAu6pIhF+UxrDedswFeG7O0z+nFf1NCCHtYEIfDayPb+Ct\n2NWMxNowbCgx9ALOABhL1XrGuCxXYt+vTW4LIAwxAoGBAIc1rwn92pIhbsypARSA\nzJIo/PaXpJYv12zlCVeHRCA+vUUqM2JHKB7Kd7xmJHzAOiwMm+sk6Uoz69a7R40l\n1fpyz478nLkjCiTAR9z4Us77vgmypdeB4YndQacaMbVEmArhcraRXkivvyQANEzF\n2XLH61SzWOJFtm8BHPjAVd6dAoGBAJG3Qj4FwaKKasf7xn4eR57RV/KJ8AzQ3Jkn\n3m1UAZ3ZzJtqNQ/TqcLAMI9y0rv3mhFkZyxg/EFK3FBEhQdAbhC+MNHPvTpA1c0O\nffkm8F4K6aMG0eEbryjLTVpIMyg99kePdcck9V8dZoXhCa51PNlf2DmW70vZ/89i\n47UOxD2xAoGARoqgA9BMIlwfBcQ/7kBw6HbmadzV+Ob+rzoZjJiuSIQly9mv0rIQ\ngIGTFPcmPrZtb7FEGb4r101fLZwPNljIb430yaqz5fzGc3Wjv+Htjot9pSYFrlwr\n/C1/LCG0HfFj4srJSrGxPeMsohx3dhKj0Gr7o8fXi0d5ALhC/0g8Idk=\n-----END RSA PRIVATE KEY-----\n";

  EXPECT_STREQ(pem_normal.c_str(), private_pem.c_str());
}

}

