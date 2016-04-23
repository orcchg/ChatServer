SET( SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR} )
SET( SOURCES
    ${SOURCE_DIR}/peer.cpp
    ${SOURCE_DIR}/protocol.cpp
    ${SOURCE_DIR}/server.cpp
    ${SOURCE_DIR}/server_menu.cpp
)
ADD_EXECUTABLE( server ${SOURCES} )
TARGET_LINK_LIBRARIES( server my_parser )

