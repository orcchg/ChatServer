#ifndef API__H__
#define API__H__

class IClient {
public:
  virtual void getLoginForm() = 0;
  virtual void postLoginForm() = 0;

  virtual void getRegisterForm() = 0;
  virtual void postRegisterForm() = 0;

  virtual void getChannels() = 0;
  virtual void changeChannel() = 0;

  virtual void sendMessage() = 0;
  virtual void receiveMessage() = 0;

  virtual void logout() = 0;
};

class IServer {
public:
  virtual void loginPeerOnChannel() = 0;
  virtual void logoutPeerFromChannel() = 0;
  virtual void logoutPeer() = 0;

  virtual void registerPeer() = 0;
  virtual void unregisterPeer() = 0;

  virtual void sendMessage() = 0;
  virtual void receiveMessage() = 0;

  virtual void broadcast() = 0;
  virtual void terminate() = 0;
};

#endif  // API__H__

