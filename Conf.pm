#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

# Finding the default interface depends on the OS
our $IS_WINDOWS;

package Conf;

use warnings;
use strict;

# Redefining the "" operator (tostring function). Allows printing objects.
use overload q("") => \&tostring;

use Net::Pcap;

# Constructor
sub new {
    my $class = shift;
    my $err;

    #our $IS_WINDOWS;
    
    my $self = {
	
	# Default input/output interface
	iface => undef,

	# MAC address of the gateway
	gateway_hwaddr => "00:00:00:00:00:00",

	# Sniff in promiscous mode or not
	promisc => 1
	};

    bless($self, $class);

    # The default interface will be the first interface found with Net::Pcap:lookupdev(),
    # except on Windows where it will be the second one.
    if(not $IS_WINDOWS) {
	$self->{iface} = Net::Pcap::lookupdev(\$err);
    }
    else {
	my %devs;
	my @alldevs = Net::Pcap::findalldevs(%devs, \$err);
	$self->{iface} = $alldevs[1];
    }

    # If any error occurred
    if(defined $err) {
	warn "Pcap: can't lookup a network device: $err (are you root/Administrator?).\n";
    }

    return $self;
}

# Converts an object to a string
sub tostring {
    my $self = shift;
    my $out = "";
    my $iface = defined($self->{iface}) ? $self->{iface} : "<none>";

    $out .= "default interface: ".$iface."\n";
    $out .= "gateway hwaddr: ".$self->{gateway_hwaddr}."\n";
    $out .= "promiscuous mode: ".$self->{promisc}."\n";

    return $out;
}

1;
