#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2011 Graham Clark, Jason Russell
# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

# Layer bounds
our $layer_bounds = {
    
    Ether => [
	      ["type", 0x800, "IP"],
              ["type", 0x8100, "Dot1Q"],
	      ["type", 0x86dd, "IPv6"],
	      ],

    ClassicBSDLoopback => [
			   ["header", 2, "IP"]
			   ],

    OpenBSDLoopback => [
			["header", 2, "IP"]
			],

    IP => [
	   ["proto", 1, "ICMP"],
	   ["proto", 6, "TCP"],
	   ["proto", 17, "UDP"]
	   ],
};

package Layer;

use warnings;
use strict;

use Carp;

# ToString function for layers ("print IP()" displays "<IPv4 |>")
use overload q("") => \&tostring;

# Redefining the "/" operator. Allows "p=IP()/TCP()" instead of "$p=add_layer(IP(), TCP())".
use overload q(/) => \&Packet::add_layer;

# Constructor
sub new {
    my $class = shift;
    my $args;

    my $self = {
	protocol => "Generic layer",

	# Array containing the fields of the protocol (see Dissectors.pm)
	fields_desc => undef,

	# Part of the string that couldn't be decoded, to be passed to the upper layer
	tobedecoded => undef
    };
    
    bless($self, $class);

    # Constructing the packet
    $self->init();
    
    # If a single argument is passed (e.g. Ether('string'))
    if(@_ == 1) {
	$args = $_[0];

	# Before getting the field values from the string, the default values are applied
	foreach (@{$self->{fields_desc}}) {
	    $self->{$_->{name}} = $_->{default_value};
	}

	# The values for this layer are retrieved from the beginning of the string.
	# build_from_string returns the end of the string, that couldn't not be decoded.
	$self->{tobedecoded} = $self->build_from_string($args);

	# If there is something left to be decoded
	if(length($self->{tobedecoded}) > 0) {

	    # layer_bounds is run throught to try to guess the upper layer.
	    # There can be several answers (array @guesses).
	    my $proto_array = $layer_bounds->{$class};
	    my @guesses;

	    foreach (@{$proto_array}) {
		my $triplet = $_;
		
		# Value from the layer_bounds triplet and the real one are compared.
		# e.g. for ["type", 0x800, "IP"], if the field "type" in the current Ethernet layer is 0x800, then the upper layer is (may be) IP.
		if($self->{$triplet->[0]} == $triplet->[1]) {
		    # Adding this possibility
		    push(@guesses, $triplet->[2]);
		}
	    }

	    # If something was guessed, the corresponding layer is created with a payload equal to what is left to be decoded.
	    if(scalar @guesses) {
		return $self/($guesses[0]->new($self->{tobedecoded}));
	    }
	    # Else, it is considered as raw data.
	    else {
		return $self/(new Raw(load=>$self->{tobedecoded}));
	    }
	}
    }

    # If arguments are passed as a hash (IP(dst=>"127.0.0.1", src=>"127.0.0.1")), or if no argument is passed
    else {
	$args = {@_};
	
	# Adding the fields to the hash $self, overwriting the default value if one is specified by the user
	# There is no verification of the validity of the arguments passed; that is to say something like "print IP(foo=>'bar')" will not display any error (the argument will just be ignored).
	foreach (@{$self->{fields_desc}}) {
	    $self->{$_->{name}} = defined $args->{$_->{name}} ? $args->{$_->{name}} : $_->{default_value};
	}
    }
    
    return $self;
}

# Converts an object to a string
sub tostring {
    my $self = shift;
    my $out = "<$self->{protocol}";
    
    # Only the fields whose values are not the default ones will be displayed
    foreach (@{$self->{fields_desc}}) {
	if ($self->{$_->{name}} ne $_->{default_value}) {
	    $out .= " $_->{name}=";
	    $out .= $_->tohuman($self->{$_->{name}});
	}
    }
    
    return $out .= " |>";
}

# Displays the packet with more details than tostring
sub show {
    my $self = shift;

    # Name of the protocol
    print "###[ $self->{protocol} ]###";
    
    # List of fields in this layer
    foreach (@{$self->{fields_desc}}) {
	print "\n$_->{name} = ", $_->tohuman($self->{$_->{name}});
    }
}

# Returns the string ready to be sent on the wire
sub tonet {
    my $self = shift;
    my $value = '';
        
    foreach (@{$self->{fields_desc}}) {
	$value .= $_->tonet($self->{$_->{name}});
    }
    
    return $value;
}

# Finishes the packet just before sending it (checksum, etc)
sub pre_send {
}

# Retrieves field values from a string and returns what was not decoded
sub build_from_string {
    my $self = shift;
    my ($string) = @_;
    my (@part, $remain);
    my $RAW = "Raw";
    my $STRFIELD = "StrField";

    # Raw is a particular case. This allows Raw("GET / HTTP 1.0\r\n\r\n")->show.
    if(ref $self eq $RAW) {
	$self->{load} = $string;
	return;
    }

    foreach (@{$self->{fields_desc}}) {

	# If $string is 0 in length here, not enough data was passed to dissect the string into a packet (e.g. IP(str(Raw(load=>"A"x19)))->show). An empty string is returned.
	return "" if(length($string) == 0);

	@part = unpack($_->{format}."a*", $string);

	# For StrField, it is expected that the result of packing is the original string
	return "" if($part[0] eq $string and ref $_ ne $STRFIELD);

	# 'remain' is the last elements of the array (unpacking "a*")
	# With this command, @part doesn't contain 'remain' anymore
	$remain = pop(@part);

	# Updating the field value
	$self->{$_->{name}} = $_->fromnet(@part);

	# Deleting the part of the string that was processed
	$string = $remain;
    }

    return $remain;
}

# Computes the checksum of a string
sub checksum {

    my $self = shift;
    my ($packet) = @_;

    my ($i, $s);
    $s = 0;

    if(length($packet) % 2 != 0) {
	$packet .= chr(0);
    }

    for($i=0;$i<length($packet)/2;$i++) {
	$s += unpack("n", substr($packet, 2*$i, 2));
    }

    $s = ($s >> 16) + ($s & 0xffff);
    $s = ~(($s >> 16) + $s) & 0xffff;

    return $s;
}

1;
