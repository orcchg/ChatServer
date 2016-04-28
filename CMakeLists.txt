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

cmake_minimum_required( VERSION 2.8 )
PROJECT( ChatServer )

# -----------------------------------------------------------------------------
# --------------------------- Common header -----------------------------------
# -----------------------------------------------------------------------------
INCLUDE_DIRECTORIES( ${CMAKE_CURRENT_BINARY_DIR} )  # for config.h
INCLUDE_DIRECTORIES( ${PROJECT_SOURCE_DIR} include )

if( CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX )
    SET( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread" )
endif()

if( DEBUG )
    MESSAGE( STATUS "Build configuration: DEBUG" )
    ADD_DEFINITIONS( -DENABLED_LOGGING=1 )
else()
    MESSAGE( STATUS "Build configuration: RELEASE" )
    ADD_DEFINITIONS( -DENABLED_LOGGING=0 )
endif()

if( ENABLE_OPENSSL )
    MESSAGE( STATUS "Openssl enabled" )
    ADD_DEFINITIONS( -DENABLE_OPENSSL=1 )
    SET( OPENSSL_LIBS openssl crypto )
else()
    MESSAGE( STATUS "Openssl disabled" )
    ADD_DEFINITIONS( -DENABLE_OPENSSL=0 )
    SET( OPENSSL_LIBS )
endif()

# -----------------------------------------------------------------------------
ADD_SUBDIRECTORY( api )
ADD_SUBDIRECTORY( client )
ADD_SUBDIRECTORY( database )
ADD_SUBDIRECTORY( parser )
ADD_SUBDIRECTORY( server )
ADD_SUBDIRECTORY( sqlite )

