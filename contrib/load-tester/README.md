## Wifidog Load Tester ##

* generate\_interfaces.sh: Sets up pseudo interfaces and creates a fake ARP
  table in /tmp/arp. Make sure that the IP addresses used do not collide with
  your real network
* mock\_auth.py: A mock auth server. Randomly grants or denies access
* fire\_requests.py: Hammers Wifidog with requests. talks to wifidog, never
  to the auth server.
* run.sh: Ties it all together. Make sure to run as root. 

