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

SET( SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR} )
SET( SOURCES
    ${SOURCE_DIR}/client.cpp
    ${SOURCE_DIR}/client_api_impl.cpp
    ${SOURCE_DIR}/utils.cpp
)

ADD_EXECUTABLE( client ${SOURCES} ${SOURCE_DIR}/run_client.cpp )
TARGET_LINK_LIBRARIES( client api my_parser ${CRYPTOR} )

if( SECURE )
    SET( SECURE_SOURCES
        ${SOURCE_DIR}/secure_client.cpp
        ${SOURCE_DIR}/run_secure_client.cpp
    )
    ADD_EXECUTABLE( s_client ${SECURE_SOURCES} ${SOURCES} )
    TARGET_LINK_LIBRARIES( s_client api my_parser ${CRYPTOR} ${OPENSSL_LIBS} )
endif()

