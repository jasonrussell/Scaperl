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

use Net::IP qw(:PROC);
use Math::BigInt;

# General field class
package Field;

# Constructor
sub new {
    my $class = shift;

    my $self = {
	name => "$_[0]",
	default_value => "$_[1]",
	format => undef
	};

    bless($self, $class);
    $self->init();

    return $self;
}

sub init {
}

# Converts from network to internal encoding
# e.g for IP->{dst}: number 2130706433 -> string "127.0.0.1" (2130706433 = 127*2^24 + 1*2^0)
sub fromnet {
    my $self = shift;
    my @values = @_;
    return $values[0];
}

# Converts from internal encoding to network
# e.g. for IP->{dst}: string "127.0.0.1"-> number 2130706433
sub tonet {
    my $self = shift;
    my ($value) = @_;
    return pack($self->{format}, $value);
}

# Converts from internal encoding to human display
# e.g. displays "0xDEADBEEF" for checksums
sub tohuman {
    my $self = shift;
    my ($value) = @_;
    return $value;
}

# Field for a string
package StrField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "A*";
}

sub tonet {
    my $self = shift;
    my ($value) = @_;
    return $value;
}

sub tohuman {
    my $self = shift;
    my ($value) = @_;
    return '"'.$value.'"';
}

# Field for one byte
package ByteField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "C";
}

# Same as ByteField, displayed in hexadecimal form
package XByteField;

our @ISA = qw(ByteField);

sub tohuman {
    my $self = shift;
    my ($value) = @_;

    my $result = sprintf("0x%x", $value);
    return $result;
}

# Field for one short (big endian/network order)
package ShortField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "n";
}

# Same as ShortField, displayed in hexadecimal form
package XShortField;

our @ISA = qw(ShortField);

sub tohuman {
    my $self = shift;
    my ($value) = @_;

    my $result = sprintf("0x%x", $value);
    return $result;
}

# Field for one long (big endian/network order)
package LongField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "N";
}

# Field for one long (little endian order)
package LELongField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "V";
}

# Field for one long (host order)
package HostOrderLongField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "L";
}

# Field for one integer
package IntField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "I";
}

# Field for an IP address
package IPField;

# inet_aton function needed
use Socket;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "N";
    $self->{ip_addr} = undef;
}

sub tonet {
    my $self = shift;
    my ($value) = @_;

    if(not defined $self->{ip_addr}) {
	$self->{ip_addr} = inet_aton($value);
    }

    return $self->{ip_addr};
}

sub fromnet {
    my $self = shift;
    my $value = $_[0];
    my($n1, $n2, $n3, $n4);

    $n1 = $value >> 24 & 255;
    $n2 = $value >> 16 & 255;
    $n3 = $value >>  8 & 255;
    $n4 = $value & 255;

    return join(".", $n1, $n2, $n3, $n4);
}

# Field for an IP address
package IPv6Field;

# inet_aton function needed
use Socket;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "N4";
    $self->{ip_addr} = undef;
}

sub tonet {
    my $self = shift;
    my ($value) = @_;

    if(not defined $self->{ip_addr}) {
	  if (Net::IP::ip_is_ipv4($value)) {
		$value = "::ffff:" . $value;
	  }
	  my $ip = new Net::IP($value, 6);
	  $self->{ip_addr} = $ip->intip();
    }

    # Get the bytes in an string array

    my @bytes;
    if (defined $self->{ip_addr}) {
	my $num = $self->{ip_addr}->copy();
	$bytes[3] = $num & 0xffffffff;
	$num->brsft(32);
	$bytes[2] = $num & 0xffffffff;
	$num->brsft(32);
	$bytes[1] = $num & 0xffffffff;
	$num->brsft(32);
	$bytes[0] = $num & 0xffffffff;
    }

    return pack($self->{format}, @bytes);
}

sub fromnet {
    my $self = shift;
    my @value = @_;
	my $val = Math::BigInt->new($value[0]);
	$val->blsft(32);
	$val += $value[1];
	$val->blsft(32);
	$val += $value[2];
	$val->blsft(32);
	$val += $value[3];
	my $ip = ip_bintoip(ip_inttobin($val));
	return $ip->print();
}


# Field for a variable length Zero field
package VarLengthZero;

our @ISA = qw(Field);

sub init {
    my $self = shift;
}

sub tonet {
    my $self = shift;
    my ($value) = @_;

    my @bytes;
	my $format = "x" x $value;
    return pack($format, @bytes);
}

sub fromnet {
    my $self = shift;
    my @value = @_;

	return "zeroes";
}


# Field for an MAC address
package MACField;

our @ISA = qw(Field);

sub init {
    my $self = shift;
    $self->{format} = "H2H2H2H2H2H2";
}

sub tonet {
    my $self = shift;
    my ($value) = @_;

    # $value can be empty (e.g. loopback device)
    if(not defined $value) {
	$value = "00:00:00:00:00:00";
    }

    # Get the bytes in an string array
    my @bytes = split(":", $value);

    return pack($self->{format}, @bytes);
}

sub tohuman {
    my $self = shift;
    my ($value) = @_;
    return $value;
}

sub fromnet {
    my $self = shift;
    my @value = @_;

    # @value is an array containing 6 bytes
    return join(":", @value);
}

1;
