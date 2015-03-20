# WifiDog #

The WiFi Guard Dog project is a complete and embeddable captive portal
solution for wireless community groups or individuals who wish to open a
free hotspot while still preventing abuse of their Internet connection.

The project's homepage is:
	http://dev.wifidog.org/

Development happens on GitHub:
	https://github.com/wifidog/

## WifiDog Gateway ##

WifiDog consists of two parts:

* auth server
* client daemon (the gateway)

This repository contains the client daemon. The client typically runs on
embedded hardware, e.g. the hotspot itself. The client is responsible for
redirecting the user to the auth server where they may authenticate
themselves. Depending on the response of the auth server, the client
lifts the access restrictions for the user.

## License ##
The project's software is released under the GPL license and is copyrighted
by its respective owners. See COPYING for details.

