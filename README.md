# ChatServer

Chat Server written in C++

Key features:
-------------

- Uses HTTP protocol, request / response parsing
- REST API
- Registration and authentication
- Password encryption
- Multi-channeling
- Broadcast and dedicated messages
- File transfer (IN PROGRESS...)
- Secure messages transfering (IN PROGRESS...)
- Server CLI with a set of commands
- Sample console Client

3rd-partly libraries:
---------------------

- SQLite
- OpenSSL
- RapidJSON

Build:
------

- mkdir build
- cd build
- cmake [-DDEBUG=true] [-DSECURE=true] ..
- make -j
    
Run:
----

- cd build
- ./server/server       (run with root priviledges as fas as it uses port 80)
- ./client/client [config_file]
- *** run as many clients as you want, use the same config_file ***
    
Config file example (see client/local.cfg)
------------------------------------------

- IP: xxx.xxx.xxx.xxx
- Port: 80              (this option is ignored)
    
License
-------

See LICENSE

