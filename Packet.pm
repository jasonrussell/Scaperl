#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

# A Packet is a linked list of Layers
package Packet;

use warnings;
use strict;

*AUTOLOAD = \&Scaperl::AUTOLOAD;

# Redefining the "" operator (tostring function). Allows printing objects.
use overload q("") => \&tostring;

# Redefining the "/" operator. Allows "p=IP()/TCP()" instead of "$p=add_layer(IP(), TCP())".
use overload q(/) => \&add_layer;

# Constructor
sub new {
    my $class = shift;
    my $args;

    my $self = {
	layers_list => undef
	};
    
    bless($self, $class);

    $args = [@_];
    $self->{layers_list} = $args;

    return $self;
}

# Converts an object to a string
sub tostring {
    my $self = shift;
    my $out = "";

    foreach (@{$self->{layers_list}}) {
	$out .= $_->tostring();
    }

    return $out;
}

# Displays the packet with more details than tostring
sub show {
    my $self = shift;

    foreach (@{$self->{layers_list}}) {
	$_->show();
	print "\n";
    }
}

# Returns the string ready to be sent on the wire
sub tonet {
    my $self = shift;
    my $value ='';
    my $payload = '';
    my ($underlayer, $prev) = (undef, undef);

    foreach (@{$self->{layers_list}}) {

	# Only some protocols need to be aware of upper layers
	if($_->{protocol} eq "IPv4" or $_->{protocol} eq "IPv6" or $_->{protocol} eq "TCP" or $_->{protocol} eq "ICMP" or $_->{protocol} eq "UDP") {
	    $payload = $self->get_payload(\$_);
	}
	
	$_->pre_send($underlayer, $payload);

	$value .= $_->tonet();
	$underlayer = $_;
	$payload = "";
    }

    return $value;
}

# Add a layer/packet/some raw data on top of a layer/packet/some raw data
sub add_layer {
    my ($lower, $upper) = @_;
    my $PACKET = "Packet";
    my $SCALAR = "";

    # Scalar/Scalar (no)
    if ((ref $lower eq $SCALAR) and (ref $upper eq $SCALAR)) {
	return new Packet(Raw(load=>$lower), Raw(load=>$upper));
    }

    # Scalar/Packet (bug?)
    elsif ((ref $lower eq $SCALAR) and (ref $upper eq $PACKET)) {
	return new Packet(Raw(load=>$lower), @{$upper->{layers_list}});
    }

    # Scalar/Layer (bug?)
    elsif ((ref $lower eq $SCALAR) and (ref $upper ne $PACKET)) {
	return new Packet(Raw(load=>$lower), $upper);
    }

    # Packet/Scalar
    elsif ((ref $lower eq $PACKET) and (ref $upper eq $SCALAR)) {
	return new Packet(@{$lower->{layers_list}}, Raw(load=>$upper));
    }

    # Packet/Packet
    elsif ((ref $lower eq $PACKET) and (ref $upper eq $PACKET)) {
	return new Packet(@{$lower->{layers_list}}, @{$upper->{layers_list}});
    }
    
    # Packet/Layer
    elsif ((ref $lower eq $PACKET) and (ref $upper ne $PACKET)) {
	return new Packet(@{$lower->{layers_list}}, $upper);
    }

    # Layer/Scalar
    elsif ((ref $lower ne $PACKET) and (ref $upper eq $SCALAR)) {
	return new Packet($lower, Raw(load=>$upper));
    }

    # Layer/Packet
    elsif ((ref $lower ne $PACKET) and (ref $upper eq $PACKET)) {
	return new Packet($lower, @{$upper->{layers_list}});
    }

    # Layer/Layer OK
    elsif ((ref $lower ne $PACKET) and (ref $upper ne $PACKET)) {
	return new Packet($lower, $upper);
    }
}

# Returns the payload of a layer
sub get_payload {
    my $self = shift;
    my ($layer) = @_;
    my $current = 0;
    my $payload = "";
    my $cat = 0;

    foreach (@{$self->{layers_list}}) {
	if(\$_ == $layer) {
	    $cat = 1;
	}
	elsif($cat == 1) {
	    $payload .= $_->tonet();
	}
    }
    
    return $payload;
}

1;
