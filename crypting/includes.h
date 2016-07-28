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

#ifndef CHAT_SERVER_INCLUDES__H__
#define CHAT_SERVER_INCLUDES__H__

#if SECURE

#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

// symmetric key in bytes
#define KEY_LENGTH SHA256_DIGEST_LENGTH
#define IV_LENGTH SHA256_DIGEST_LENGTH >> 1

// key lengths in bits
#define RSA_KEYLEN 2048
#define AES_KEYLEN 256
#define AES_ROUNDS 6

#define ERROR_BUFFER_SIZE 256
#define KEY_SIZE_BITS RSA_KEYLEN
#define KEY_PUBLIC_EXPONENT 65537

#endif  // SECURE

#endif  // CHAT_SERVER_INCLUDES__H__
