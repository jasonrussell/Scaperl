#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2011,2012 Graham Clark, Jason Russell
# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

use warnings;
use strict;

use Carp;
use POSIX;
use Storable;
use Clone qw(clone);



# MTU
our $MTU = 1500;

# Converts a packet to a string
sub str {
    my ($packet) = @_;
    return $packet->tonet();
}

# Sniff packets on an interface
sub sniff {
    my $args = {@_};
    my $err = '';
    my $FOREVER = -1;
    my $STORE = 1;

    # timeout = 0 seems to be a problem on some platforms
    my $TIMEOUT = 1;

    my $OFFLINE = 0;
    my $OPTIMIZE = 1;
    our $conf;

    my $count = defined($args->{count}) ? $args->{count} : $FOREVER;

    # not used yet
    my $store = defined($args->{store}) ? $args->{store} : $STORE;

    # not used yet
    my $offline = defined($args->{offline}) ? $args->{offline} : $OFFLINE;

    my $prn = defined($args->{prn}) ? $args->{prn} : \&sniff_simple;
    my $lfilter = defined($args->{lfilter}) ? $args->{lfilter} : undef;
    my $timeout = defined($args->{timeout}) ? $args->{timeout} : $TIMEOUT;
    my $iface = defined($args->{iface}) ? $args->{iface} : $conf->{iface};
    my $promisc = defined($args->{promisc}) ? $args->{promisc} : $conf->{promisc};

    # Can't sniff without a valid interface
    if(not defined $iface) {
	croak "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator.\n";
    }

    # OK, opening the interface with PCAP
    our $pcap = Net::Pcap::open_live($iface, $MTU, $promisc, $timeout, \$err);

    if(not defined $pcap) {
	croak "Pcap: can't open device $iface: $err\n";
    }

    # Getting the link type
    my $linktype = Net::Pcap::datalink($pcap);

    # PCAP filtering
    if(defined $lfilter) {
	my ($net, $mask, $filter);

	# Getting the netmask for filter compilation
	if(Net::Pcap::lookupnet($iface, \$net, \$mask, \$err) != 0) {
	    croak "Pcap: can't get the netmask for $iface: $err\n";
	}

	# Filter compilation
	if(Net::Pcap::compile($pcap, \$filter, $lfilter, $OPTIMIZE, $mask) != 0) {
	    croak "Pcap: can't compile filter $lfilter: $err\n";
	}

	# Setting the filter
	if(Net::Pcap::setfilter($pcap, $filter) != 0) {
	    croak "Pcap: can't set filter: $err\n";
	}

	# Freeing memory
	Net::Pcap::freecode($filter);
    }

    # Sniffing in progress
    my $linktype_name = Net::Pcap::datalink_val_to_name($linktype);
    my $linktype_desc = Net::Pcap::datalink_val_to_description($linktype);
    print "listening on $iface, link type is $linktype_name ($linktype_desc)\n";

    # ^C is caught by the function sniff_sigint_handler
    $SIG{INT} = \&sniff_sigint_handler;

    # The last field "user_data" is used to pass the link type.
    my $loop_return = Net::Pcap::loop($pcap, $count, $prn, $linktype);

    if($loop_return == -1) {
	croak "Error while sniffing: $err";
    }

    # Closing
    $SIG{INT} = 'DEFAULT';
    Net::Pcap::close($pcap);
}

# function added to perform fragmentation, for IPv4 right now
sub fragment {
    my ($packet, $fragmentsize) = @_;
    my $fragmentoffset;
    my @scaperlpacketlist = ();

    # we need to get closer to the octet
    if (!($fragmentsize%8 == 0)) {
        $fragmentoffset = 8-($fragmentsize%8);
        $fragmentsize = $fragmentsize + $fragmentoffset;
    }

    # ipv4 flag
    my $isipv4on = 0;
    my $layerindex = 0;

    for (my $i=0; $i < $#{$packet->{layers_list}}; $i++) {

        # IPv4 address
        if (ref $packet->{layers_list}[$i] eq "IP") {
            $layerindex = $i;
            $isipv4on = 1;
            last;
        }

    }

    # ipv4 layer was found, fragment that IP layer
    if ($isipv4on) {

        my $ippayloadsize =  length($packet->get_payload((\$packet->{layers_list}[$layerindex])));
        my $datacount = ceil($ippayloadsize/$fragmentsize);


        my $offset = 0;

        # create a fragmented packet with the payload equal to fragment size
        for (my $i=0;$i<$datacount;$i++) {
           
            my $scaperlpacket = "";
            $offset = $offset + ($fragmentsize/8);
           
            # each layer up until the IP layer will stay the same
            for (my $j=0;$j<($layerindex+1);$j++) {

                my $layer = $packet->{layers_list}[$j];

                # some things need to get modified
                if (ref $layer eq "IP") {

                    # last packet
                    if ($j == $layerindex) {
                        $layer->{flags_offset} = $offset;
                    }
                   
                    # other fragments
                    else {
                       # 0x2000 is More Fragments
	               $layer->{flags_offset} = 0x2000 | $offset;
                    }
               
                }
                
                if (ref $scaperlpacket ne "Scaperl") {
                    $scaperlpacket = $layer;
                }
                else {
                   $scaperlpacket = $scaperlpacket / $layer;
                }
            }

            my $newscaperlpacket = clone($scaperlpacket);


            # packet up until IP Layer stayed the same, IP layer fragmented
            # keep all layers copied over until we run into the Raw data
            my $k = $layerindex;

            while ($k < $#{$packet->{layers_list}}+1) {

                if (ref $packet->{layers_list}[$k] eq "Raw") {
                    my $rawpayload = $packet->{layers_list}[$k]->{load};
                    my $quotient = ceil(length($rawpayload)/$datacount);
                    my $payloadoffset = $i*$quotient;

                    my $rawpayloadfragment = "";
                    if (length(substr($rawpayload,$payloadoffset)) >= $quotient) {
                        $rawpayloadfragment = substr($rawpayload,$payloadoffset,$quotient);
                    }
                    else {
                        $rawpayloadfragment = substr($rawpayload,$payloadoffset);
                    }
                    $newscaperlpacket = $newscaperlpacket/$rawpayloadfragment;
                }

                else {
                    $newscaperlpacket = $newscaperlpacket/$packet->{layers_list}[$k];
                }

                $k++;


            }

           push(@scaperlpacketlist,$newscaperlpacket);
        }


    }

    return \@scaperlpacketlist;

}

# Default callback function for sniff (simple packet display)
sub sniff_simple {
    my ($linktype, $header, $packet) = @_;

    # Ethernet or Linux loopback
    if($linktype == Net::Pcap::DLT_EN10MB) {
	print "\n$header->{tv_sec}.$header->{tv_usec} ", Ether($packet),"\n";
    }

    # Classic BSD loopback
    elsif($linktype == Net::Pcap::DLT_NULL) {
	print "\n$header->{tv_sec}.$header->{tv_usec} ", ClassicBSDLoopback($packet),"\n";
    }

    # OpenBSD loopback
    elsif($linktype == Net::Pcap::DLT_LOOP) {
	print "\n$header->{tv_sec}.$header->{tv_usec} ", OpenBSDLoopback($packet),"\n";
    }

    # Unknown link type
    else {
	warn "Unknown link type: $linktype\n";
	print "raw packet=|$packet| \n";
    }
}

# ^C during a sniff stops sniffing
sub sniff_sigint_handler {
    our $pcap;
    Net::Pcap::breakloop($pcap);
    print "\nStopped by user.";
}

# Sends a packet at layer 3.
sub sd {
    my ($packet) = @_;
    my $LOOPBACK_DEVICE_PREFIX = "lo";
    our ($conf, $IS_BSD, $IS_OPENBSD);
    my $iface = $conf->{iface};

    # Can't do anything without a valid interface
    if(not defined $iface) {
	croak "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator.\n";
    }

    # Sending the packet with sendp
    # If we're sending on a loopback interface, we must be careful because of the different
    # fake headers.
    # The loopback device is "lo" on Linux and "lo0" on BSD; there is no loopback device on
    # Windows.
    # On BSD, a 4-byte header is used for loopback and there is a special case for OpenBSD;
    # on Linux, it is an Ethernet header.
    if($IS_BSD and index($conf->{iface}, $LOOPBACK_DEVICE_PREFIX) != -1) {
	if($IS_OPENBSD) {
	    sendp(OpenBSDLoopback()/$packet);
	}
	else {
	    sendp(ClassicBSDLoopback()/$packet);
	}
    }
    else {
	  my $typ = 0x800;

	  if (((ref $packet eq "Packet") && (ref $packet->{layers_list}[0] eq "IPv6")) || (ref $packet eq "IPv6")) {
		$typ = 0x86dd;
	  }

	  if (((ref $packet eq "Packet") && (ref $packet->{layers_list}[0] eq "Dot1Q")) || (ref $packet eq "Dot1Q")) {
		$typ = 0x8100;
	  }

	  sendp(Ether(type=>$typ)/$packet);
    }
}

# Sends a packet at layer 2
sub sendp {
    my ($packet) = @_;

    # Getting global variables
    our ($IS_LINUX, $HAVE_LIBDNET, $pcap, $conf);

    my $PACKET = "Packet";
    my $ETHERNET = "Ether";
    my $IP = "IP";
    my $LOOPBACK_DEVICE = "lo";
    my ($iface_info, $layer2_src, $layer2_dst, $layer3_src, $err);
    my $iface = $conf->{iface};
    my $promisc = $conf->{promisc};
    my $timeout = 0;

    # Can't do anything without a valid interface
    if(not defined $iface) {
	croak "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator.\n";
    }

    # Default values
    my $IP_default_src = IP()->{src};
    my $Ether_default_src = Ether()->{src};
    my $Ether_default_dst = Ether()->{dst};

    # Getting source information with Libdnet if available
    if($HAVE_LIBDNET) {
	$iface_info = Net::Libdnet::intf_get($conf->{iface});

	if(not defined $iface_info->{addr}) {
	    croak "Libdnet: interface '",$conf->{iface},"' is not valid.\n";
	}

	# addr field is "a.b.c.d/mask", splitting at '/'
	($layer3_src) = split(/\//, $iface_info->{addr});

	$layer2_src = $iface_info->{link_addr};

    }
    # Otherwise, taking the default value
    else {
	$layer3_src = $IP_default_src;
	$layer2_src = $Ether_default_src;
    }

    # Destination MAC is taken from the configuration. On Linux, if the packet is to be sent on
    # the loopback device, it must be null.
    if($IS_LINUX and index($conf->{iface}, $LOOPBACK_DEVICE) != -1) {
	$layer2_dst = $Ether_default_src;
    }
    else {
	$layer2_dst = $conf->{gateway_hwaddr};
    }
    
    # Modifying the IP layer (only if the values are the default ones)
    # If $packet is a Packet
    if(ref $packet eq $PACKET) {

	# If the second layer is IP and src is the default value
	if(ref $packet->{layers_list}[1] eq $IP and $packet->{layers_list}[1]->{src} eq $IP_default_src) {
	    $packet->{layers_list}[1]->{src} = $layer3_src;
	}
    }
    # If $packet is a Layer and src is the default value
    elsif(ref $packet eq $IP and $packet->{src} eq $IP_default_src) {
	$packet->{src} = $layer3_src;
    }

    # Modifying the Ethernet layer (only if the values are the default ones)
    # If $packet is a Packet
    if(ref $packet eq $PACKET) {
	
	# If the first layer is Ethernet and src/dst are the default values
	if(ref $packet->{layers_list}[0] eq $ETHERNET) {
	    $packet->{layers_list}[0]->{src} = $layer2_src if($packet->{layers_list}[0]->{src} eq $Ether_default_src);
	    $packet->{layers_list}[0]->{dst} = $layer2_dst if($packet->{layers_list}[0]->{dst} eq $Ether_default_dst);
	}
    }
    # If $packet is an Ethernet layer and src/dst are the default values
    elsif(ref $packet eq $ETHERNET) {
	$packet->{src} = $layer2_src if($packet->{src} eq $Ether_default_src);
	$packet->{dst} = $layer2_dst if($packet->{dst} eq $Ether_default_dst);
    }
    
    # Opening the interface
    if(not defined $pcap) {
	  $pcap = Net::Pcap::open_live($iface, $MTU, $promisc, $timeout, \$err);
    }

    if(not defined $pcap) {
	croak "Pcap: can't open device: $err\n";
    }

    # Get stats
    my %stats = ();


   
    # Sending the packet with PCAP
    if(Net::Pcap::sendpacket($pcap, $packet->tonet()) == 0) {
        Net::Pcap::stats($pcap,\%stats);
        my $drop = $stats{'ps_drop'};
        
        # we have some dropped packets, reopen the packet capture device
        # and send the packet again
        while ($drop > 0) {
	    Net::Pcap::close($pcap);
	    $pcap = Net::Pcap::open_live($iface, $MTU, $promisc, $timeout, \$err);

            if(not defined $pcap) {
	        croak "Pcap: can't open device: $err\n";
            }

            Net::Pcap::sendpacket($pcap, $packet->tonet());
            Net::Pcap::stats($pcap,\%stats);
            $drop = $stats{'ps_drop'};

        }
		#print "Sent on $iface.\n";
    }
    else {
	croak "Pcap: error while sending packet on $iface\n";
    }

	# gcla
	#Net::Pcap::close($pcap);
}

# given a filename and optionally a count of packets to read (-1 disables it),
# returns an array of packets in the Scaperl
# The only caveats are that this was only tested for IPv4 and the packets are
# not out of the norm (e.g VLANs)
sub rdpcap {

    my ($filename, $count) = @_;

    if (not defined $count) {
        $count = -1;
    }
    my $magic = "";
    my $header = "";
    my $scaperlpacket = "";
    my @scaperllist = ();
    my $packetsread = 0;
    my $packet = "";

    # little endian short and long by default
    my $ushort = "v";
    my $ulong = "V";

    # read pcap file
    open FILE, "<$filename" or die $!;
    my $numbytes = read FILE, $magic, 4;

    if ($numbytes != 4) {die "Not a valid pcap capture file (too short)" };

    # detected file is big endian
    if ($magic eq "\xa1\xb2\xc3\xd4") {
        $ushort = "n";
        $ulong = "N";
    }
    # detected file is little endian
    elsif ($magic eq "\xd4\xc3\xb2\xa1") {
        # do nothing
    }
    else {
        die "Not a valid pcap capture file (bad magic)\n";
    }

    # read the global header data - doing nothing with them but may need them
    # later
    $numbytes = read FILE, $header, 20;

    if ($numbytes<20) {
        die "Invalid pcap file (got past the magic, but too short)\n";
    }

    my ($version_major, $version_minor, $thiszone, $sigfigs, $snaplen, $network) = unpack($ushort . $ushort . $ulong . $ulong . $ulong . $ulong,$header);

    # read packets

    # initial packet read into header
    $numbytes = read FILE, $header, 16;

    # Either the amount of data read for the packet is correct or the amount 
    # of packets read is specified and is not read yet
    while (($numbytes == 16) && ($count == -1 || ($count > -1 && $packetsread < $count)) ) {

        # frame headers
	my ($ts_sec,$ts_usec,$incl_len,$orig_len) = unpack($ulong . $ulong . $ulong . $ulong,$header);
	$numbytes = read FILE, $packet, $incl_len;

        $scaperlpacket = Ether($packet);
        push(@scaperllist,$scaperlpacket);

        $numbytes = read FILE, $header, 16;
        $packetsread++;
    }

    return \@scaperllist;

}

sub close {
  # gcla
  our $pcap;
  Net::Pcap::close($pcap);
  undef $pcap;
}

1;
