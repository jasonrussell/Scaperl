#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

# General help
sub help {
    my ($command) = @_;
    
    if(not defined $command) {
	print <<EOF;
This is Scaperl, a portable, customizable packet creation and sending/sniffing tool written in Perl. It is based on PCAP and libdnet (and their respective Perl wrappers). It was tested on NetBSD, GNU/Linux and Windows XP and should theoretically work on some other platforms such as FreeBSD, OpenBSD, Mac OS X and proprietary Unixes.

See http://sylvainsarmejeanne.free.fr/projects/scaperl for more information.

With Scaperl, you can:
- create custom packet: \$p=IP(dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
- send custom packets at layer 3: sd(\$p)
- send custom packets at layer 2: sendp(Ether()/\$p)
- sniff on an interface: sniff(iface=>"eth1")
- dissect a string to a recreate the packet: \$s=str(\$p);print "string=\$s";print "result=",IP(\$s)

Available dissectors:
@DISSECTOR_LIST

Available functions (type "help '<function>'" to have detailed information):
@FUNCTION_LIST
EOF
}
    # Exécution de la function d'aide
    else {
	eval $command."_help";	
    }
}

# Help on str
sub str_help {
    print <<EOF
This function transforms a packet into a string ready to be sent on the wire (that is to say, it \"packs\" it). Note that some characters may not be displayable.

example> \$p=IP(dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> print str(\$p)
E:@m@é·gPP DGET / HTTP 1.0
EOF
}

# Help on sniff
sub sniff_help {
    print <<EOF
This function captures packets on an interface. The default capture interface is determined by the PCAP library and is stored in \$conf->{iface} (currently "$conf->{iface}").

Without any argument, sniff captures on the default interface:
example> sniff
listening on eth0, link type is EN10MB (Ethernet)
1158608918.45960 <Ethernet dst=00:11:22:33:44:55 src=55:44:33:22:11:00 |><IPv4 len=84 flags_offset=16384 proto=1 chksum=0x7c0f src=1.2.3.4 dst=4.3.2.1 |><ICMP chksum=17905 id=16922 seq=1 |>
1158608918.124147 <Ethernet dst=55:44:33:22:11:00 src=00:11:22:33:44:55 |><IPv4 len=84 flags_offset=16384 ttl=244 proto=1 chksum=0xc80e src=4.3.2.1 dst=1.2.3.4 |><ICMP type=0 chksum=19953 id=16922 seq=1 |>

The following arguments are available (with the default values between brackets):
- iface: the interface to listen on (\$conf->{iface}, currently "$conf->{iface}")
- prn: a function that will be called for each packet received (sniff_simple)
- lfilter: a PCAP filter (undef)
- count: the number of packets to capture. An argument less than or equal to 0 will read "loop forever" (-1)
- promisc: capture in promiscuous mode or not (\$conf->{promisc}, currently "$conf->{promisc}")
- timeout: capture timeout in milliseconds (0, seems not to work?)
- store: not implemented yet
- offline: not implemented yet

The prn argument is the most interesting one, it allows you to customize the behaviour of the sniff function:

example> sub my_prn {my (\$linktype, \$header, \$packet) = \@_; print "GOT ONE: raw=|\$packet|\\n"}
example> sniff(iface=>"eth1", prn=>"my_prn", lfilter=>"icmp")
listening on eth0, link type is EN10MB (Ethernet)
GOT ONE: raw=|Ë
               g¦Pp4ET@@É·RïËIÑU¶\bú¢8Eº£

Note that by default, packets captured are not stored in memory for performance reason. To stop sniffing, press ^C.
EOF
}

# Help on sd
sub sd_help {
    print <<EOF
This function sends a packet at layer 3 on the default interface (\$conf->{iface}, currently "$conf->{iface}"). If Libdnet is available, source IP address is automatically filled according to this interface.

example> \$p=IP(dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> sd(\$p)
Sent.
EOF
}

# Help on sendp
sub sendp_help {
    print <<EOF
This function sends a packet at layer 2 on the default interface (\$conf->{iface}, currently "$conf->{iface}"). If Libdnet is available, source Ethernet address and source IP address are automatically filled according to this interface.

example> \$p=Ether()/IP(dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> sendp(\$p)
Sent.
EOF
}

1;
