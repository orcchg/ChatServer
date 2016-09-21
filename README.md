# ChatServer

Chat Server written in C++

<a style="margin-bottom: 0;" href='https://play.google.com/store/apps/details?id=com.orcchg.chatclient'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_us/badges/images/generic/en_badge_web_generic.png' height="80px"/></a>

Key features:
-------------

- Uses HTTP protocol, request / response parsing
- REST API
- Registration and authentication
- Password encryption
- Multi-channeling
- Broadcast and dedicated messages
- File transfer (IN PROGRESS...)
- Secure messages transfering
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
- ./server/server [port]       "run with root priviledges if port is 80"
- ./client/client [config_file]
- *** run as many clients as you want, use the same config_file ***
    
Config file example (see client/local.cfg)
------------------------------------------

- IP: xxx.xxx.xxx.xxx
- Port: 80

Secure messaging
----------------

Once two different clients have successfully logged in, they can start communicating securely.
Each of them must perform the following commands first:

- .pk - obtain an RSA key pair and store it in memory (key pair is generated if not exists).
- .pe id - send public key to another peer with id specified.

Then some of peers could ask for secure communication with another peer typing the command:

- .pr id - ask for secure communication to peer with id

Another peer could accept or reject an incoming request:

- .pc id - accept request from peer with id and start secure communication.
- .pd id - reject request from peer with id. Communicate without encryption.

Any peer could abort secure communication at any time:

- .px id - abort (or reject, if not previously accepted) secure communication.

Secure communication aborts automatically, when any of peers logs out or gets dropped from chat.
    
License
-------

See LICENSE

Version
-------

Version 1.3 is GPL licensed for non-commercial. This version is freezed and is outdated.
Currently production version is 1.5.1 which is not open-source anymore.

Checkout ChatClient android app on Google Play !
