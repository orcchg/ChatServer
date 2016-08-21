#   HTTP Chat server with authentication and multi-channeling.
#
#   Copyright (C) 2016  Maxim Alov
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#
#   This program and text files composing it, and/or compiled binary files
#   (object files, shared objects, binary executables) obtained from text
#   files of this program using compiler, as well as other files (text, images, etc.)
#   composing this program as a software project, or any part of it,
#   cannot be used by 3rd-parties in any commercial way (selling for money or for free,
#   advertising, commercial distribution, promotion, marketing, publishing in media, etc.).
#   Only the original author - Maxim Alov - has right to do any of the above actions.

SET( SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR} )
SET( SOURCES
    ${SOURCE_DIR}/aes_cryptor.cpp
    ${SOURCE_DIR}/evp_cryptor.cpp
    ${SOURCE_DIR}/rsa_cryptor.cpp
    ${SOURCE_DIR}/cryptor.cpp
    ${SOURCE_DIR}/crypting_util.cpp
    ${SOURCE_DIR}/random_util.cpp
    ${SOURCE_DIR}/sym_key.cpp
)
ADD_LIBRARY( ${CRYPTOR} SHARED ${SOURCES} )
TARGET_LINK_LIBRARIES( ${CRYPTOR} ${OPENSSL_LIBS} common )

