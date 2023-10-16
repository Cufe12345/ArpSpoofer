# ArpSpoofer
An Arp Spoofer programmed in C#

# Functionality
Supports arp spoofing attacks where the packets will still be passed on to the router and back to the target so you can view all packets going through.

Support denial of service attack where the packets wont be passed to the router meaning the target has no internet connection.

Support finding devices IP and mac addresses on a local network

# Arguments
-a [victim ip] [Gateway-ip]'  for an arp spoof attack
-d [victim ip] [Gateway-ip]' for an denial of service attack on victim
-s' to search for devices on your network

# Warning
It is illegal to use this on networks and devices which arent yours, I take no responsibility for any malicious use of this program/code, this is for educational purposes only!
