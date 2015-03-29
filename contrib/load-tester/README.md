## Wifidog Load Tester ##

* generate\_interfaces.sh: Sets up pseudo interfaces and creates a fake ARP
  table in /tmp/arp. Make sure that the IP addresses used do not collide with
  your real network
* mock\_auth.py: A mock auth server. Randomly grants or denies access
* fire\_requests.py: Hammers Wifidog with requests. talks to wifidog, never
  to the auth server.
* run.sh: Ties it all together. Make sure to run as root. 

Once you think the script has run long enough, kill run.sh and look at
valgrind.log. You have to clean up after the script yourself, e.g. kill
mock\_auth.py separately and run **./generate_interfaces.sh stop**

### Note on ARP tables ###

Although generate\_interfaces.sh will add random MAC addresses
to the virtual interfaces, these will not show up in the local
ARP table. The ARP table only lists remote systems. Even with the
**publish** flag set, the ARP table entry will list an all-zero MAC
address. For this reason, the script generates a fake ARP table
and passes it to wifidog with the **-a** switch.

The macvlan type virtual interface used by generate\_interfaces.sh
is still useful if you load-test a remote wifidog instance. In this case,
the remote ARP table will (hopefully) be populated correctly.
