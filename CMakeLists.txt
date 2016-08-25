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

cmake_minimum_required( VERSION 2.8 )
PROJECT( ChatServer )
SET( D_VERSION "1.5" )
MESSAGE( STATUS "Version ${D_VERSION}" )

# -----------------------------------------------------------------------------
# --------------------------- Common header -----------------------------------
# -----------------------------------------------------------------------------
INCLUDE_DIRECTORIES( ${CMAKE_CURRENT_BINARY_DIR} )  # for config.h
INCLUDE_DIRECTORIES( ${PROJECT_SOURCE_DIR} include )

if( CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX )
    SET( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3 -pthread" )
endif()

if( DEBUG )
    MESSAGE( STATUS "Build configuration: DEBUG" )
    ADD_DEFINITIONS( -DENABLED_LOGGING=1 )
    ADD_DEFINITIONS( -DD_VERSION="${D_VERSION}-DEBUG" )
else()
    MESSAGE( STATUS "Build configuration: RELEASE" )
    ADD_DEFINITIONS( -DENABLED_LOGGING=0 )
    ADD_DEFINITIONS( -DD_VERSION="${D_VERSION}-RELEASE" )
endif()

if( SECURE )
    MESSAGE( STATUS "Security enabled" )
    FIND_LIBRARY( CRYPTO_LIB NAMES crypto )
    FIND_LIBRARY( SSL_LIB NAMES ssl )
    SET( OPENSSL_LIBS ${CRYPTO_LIB} ${SSL_LIB} )
    SET( CRYPTOR cryptor )
    ADD_DEFINITIONS( -DSECURE=1 )
    ADD_SUBDIRECTORY( crypting )
else()
    MESSAGE( STATUS "Security disabled" )
    SET( OPENSSL_LIBS )
    SET( CRYPTOR )
    ADD_DEFINITIONS( -DSECURE=0 )
endif()

if( WITH_TEST )
    MESSAGE( STATUS "Build with tests" )
    ADD_SUBDIRECTORY( googletest )
    ADD_SUBDIRECTORY( test )
endif()

# -----------------------------------------------------------------------------
ADD_SUBDIRECTORY( api )
ADD_SUBDIRECTORY( client )
ADD_SUBDIRECTORY( common )
ADD_SUBDIRECTORY( database )
ADD_SUBDIRECTORY( parser )
ADD_SUBDIRECTORY( server )
ADD_SUBDIRECTORY( sqlite )

