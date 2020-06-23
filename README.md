# tiny-webrtc-gw
Welcome to the tiny-webrtc-gw readme!

tiny-webrtc-gw is a self-contained webRTC video/audio conferencing (many-to-many) server daemon for linux.

The simplest way to roll-your-own (secure) webRTC video broadcast service.

(screenshot here)
![screenshot](http://www.domain17.net/justin/tiny-webrtc-gw-screenshot.png)

Head over to the demo!

[https://weephone.domain17.net](https://weephone.domain17.net/)

Hot features:
* Very low latency 1-many streaming
* HD stream support
* text chat room
* highly scalable (native c/c++ code)
* end-to-end encrypted
* chrome/firefox/opera/safari (iOS) support
* easy compilation (just git checkout --recursive and "make all")


Demo at https://weephone.domain17.net/


Building:

building requires 'go' to compile boringssl (so install those packages)

Make sure you checked out the websocket git submodule by checking out with --recursive or
doing
git submodule init ws && git submodule update ws

from the base directory just run 'make all'.

You will need to edit at least one line in config.txt so the built-in STUN server
knows its own IP address (relative to the clients connecting, if you're using NAT).
Go to whatismyipaddress.com and replace the udpserver_addr=x.x.x.x line with
your own IP address.

