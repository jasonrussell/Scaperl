#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

use warnings;
use strict;

# Dissector for Ethernet
package Ether;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

# Constants for Ethernet type field
use constant ETH_TYPE_IP => 0x0800;

sub init {
    my $self = shift;

    $self->{protocol} = "Ethernet";
    $self->{fields_desc} =
	[
	 MACField("dst", "00:00:00:00:00:00"),
	 MACField("src", "00:00:00:00:00:00"),
	 XShortField("type", ETH_TYPE_IP)
	 ];
}

# Dissector for Dot1Q (for VLANs)
package Dot1Q;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

use constant ETH_TYPE_IP => 0x0800;

sub init {
    my $self = shift;

    $self->{protocol} = "Dot1Q";

    # all these fields need to be initially available
    $self->{fields_desc} = 
    [
     XShortField("prio",0),
     XShortField("id",0),
     XShortField("vlan",1),
     XShortField("priority_cfi_id",1),
     XShortField("type", ETH_TYPE_IP)
    ];
}

sub pre_send {
    my $self = shift;
    my ($underlayer, $payload) = @_;

    # first 3 bits
    my $priority = ($self->{prio} & 0x07) << 13;
    # next 1 
    my $cfi = ($self->{id} & 0x01) << 12;
    # remaining 12 bits
    my $id = $self->{vlan} & 0x07F;

    my $priority_cfi_id = ($priority + $cfi + $id);

    $self->{priority_cfi_id} = $priority_cfi_id;

    # these will only be sent out for crafting
    $self->{fields_desc} = 
    [
     XShortField("priority_cfi_id",$priority_cfi_id),
     XShortField("type", ETH_TYPE_IP)
    ];

}



# Dissector for ZeroPadding
package ZeroPadding;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

sub init {
    my $self = shift;

    $self->{protocol} = "ZeroPadding";
    $self->{fields_desc} =
	[
	 VarLengthZero("len", "14")
	 ];
}

# Dissector for IPv4
package IP;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

# Constants for IP proto field
use constant IP_PROTO_TCP => 6;

sub init {
    my $self = shift;

    $self->{protocol} = "IPv4";
    $self->{fields_desc} =
	[
	 XByteField("version_ihl", 0x45),
	 XByteField("tos", 0),
	 ShortField("len", 20),
	 XShortField("id", 0),
	 ShortField("flags_offset", 0),
	 ByteField("ttl", 64),
	 ByteField("proto", IP_PROTO_TCP),
	 XShortField("chksum", 0),
	 IPField("src", "127.0.0.1"),
	 IPField("dst", "127.0.0.1"),
	 ];
}

sub pre_send {
    my $self = shift;
    my ($underlayer, $payload) = @_;

    # Total length
    $self->{len} = 20 + length($payload);

    # Checksum
    if ($self->{chksum} == 0) {
        $self->{chksum} = 0;
        $self->{chksum} = $self->checksum($self->tonet());
    }
}

# Dissector for IPv6
package IPv6;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

# Constants for IP proto field
use constant IP_PROTO_TCP => 6;

sub init {
    my $self = shift;

    $self->{protocol} = "IPv6";
    $self->{fields_desc} =
	[
	 XByteField("version_ihl", 0x60),
	 XByteField("dummy1", 0),
	 ShortField("dummy2", 0),
	 ShortField("len", 20),
	 ByteField("proto", IP_PROTO_TCP),
	 ByteField("hop", 64),
	 IPv6Field("src", "::1"),
	 IPv6Field("dst", "::1"),
	 ];
}

sub pre_send {
    my $self = shift;
    my ($underlayer, $payload) = @_;

    # Total length
    $self->{len} = length($payload);
}

# Dissector for ICMP
package ICMP;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

# Constants for ICMP type field
use constant ICMP_TYPE_ECHO_REQUEST => 8;

sub init {
    my $self = shift;

    $self->{protocol} = "ICMP";
    $self->{fields_desc} =
	[
	 ByteField("type", ICMP_TYPE_ECHO_REQUEST),
	 ByteField("code", 0),
	 XShortField("chksum", 0),
	 XShortField("id", 0),
	 XShortField("seq", 0)
	 ];
}

sub pre_send {
    my $self = shift;
    my ($underlayer, $payload) = @_;

    # Checksum
    $self->{chksum} = 0;
    $self->{chksum} = $self->checksum($self->tonet().$payload);
}

# Dissector for Raw
package Raw;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

sub init {
    my $self = shift;

    $self->{protocol} = "Raw";
    $self->{fields_desc} =
	[
	 StrField("load", ""),
	 ];
}

# Dissector for TCP
package TCP;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

sub init {
    my $self = shift;

    $self->{protocol} = "TCP";
    $self->{fields_desc} =
	[
	 ShortField("sport", 1024),
	 ShortField("dport", 80),
	 IntField("seq", 0),
	 IntField("ack", 0),
	 ByteField("dataofs_reserved", 0x50),
	 XByteField("flags", 0x2),
	 ShortField("window", 8192),
	 XShortField("chksum", 0),
	 ShortField("urgptr", 0),
	 ];
}

sub pre_send {
    my $self = shift;
    my ($underlayer, $payload) = @_;
    my $IP = "IP";

    # To compute the TCP checksum, the IP underlayer is needed. Otherwise, the chksum field is left equal to 0.
    if(ref $underlayer eq $IP) {
	
	# Getting IP addresses from the IPFields
	my $ip_src = $underlayer->{fields_desc}[8]->tonet();
	my $ip_dst = $underlayer->{fields_desc}[9]->tonet();

	my $pseudo_header = pack("a4a4nn",
				 $ip_src,
				 $ip_dst,
				 $underlayer->{proto},
				 length($self->tonet().$payload));

        if ($self->{chksum} == 0) {
	$self->{chksum} = 0;
	$self->{chksum} = $self->checksum($pseudo_header.$self->tonet().$payload);
        }
    }
}

# Dissector for UDP
package UDP;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

sub init {
    my $self = shift;

    $self->{protocol} = "UDP";
    $self->{fields_desc} =
	[
	 ShortField("sport", 53),
	 ShortField("dport", 53),
	 ShortField("len", 8),
	 XShortField("chksum", 0)
	 ];
}

# Almost the same as TCP
sub pre_send {
    my $self = shift;
    my ($underlayer, $payload) = @_;

    # Total length
    $self->{len} = 8 + length($payload);

    return TCP::pre_send($self, $underlayer, $payload)
}

# Dissector for the classic BSD loopback header (NetBSD, FreeBSD and Mac OS X)
package ClassicBSDLoopback;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

sub init {
    my $self = shift;

    $self->{protocol} = "Classic BSD loopback";
    $self->{fields_desc} =
	[
	 HostOrderLongField("header", 2),
	 ];
}

# Dissector for the OpenBSD loopback header
package OpenBSDLoopback;

our @ISA = qw(Layer);
*AUTOLOAD = \&Scaperl::AUTOLOAD;

sub init {
    my $self = shift;

    $self->{protocol} = "OpenBSD loopback";
    $self->{fields_desc} =
	[
	 LELongField("header", 2),
	 ];
}

1;
