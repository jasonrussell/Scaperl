#! /usr/bin/env perl
# -*- coding: iso-8859-1 -*-

# Copyright (C) 2011 Graham Clark, Jason Russell 
# Copyright (C) 2006 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
# the GNU General Public License for more details. 

package Scaperl;

use warnings;
use strict;
use Clone;

# Getting the OS. This will be useful for sending packets on the loopback device.
my $os = $^O;
our $IS_OPENBSD = $os eq "openbsd" ? 1 : 0;
our $IS_BSD = index($os, "bsd") != -1 ? 1 : 0;
our $IS_LINUX = $os eq "linux" ? 1 : 0;
our $IS_WINDOWS = ($os eq "MSWin32" or $os eq "cygwin") ? 1 : 0;

# Knowing whether we have libdnet or not will be useful for sending packets.
our $HAVE_LIBDNET = 1;

# Importing non-standard modules, they are all mandatory.
BEGIN {
    # Carp module (croak, warn, etc)
    eval "use Carp";
    die "FATAL: can't load module Carp," if $@;

    # Pcap module
    eval "use Net::Pcap";
    die "FATAL: can't load module Net::Pcap," if $@;
}

# Libdnet module (not mandatory)
eval "use Net::Libdnet";
if($@) {
    warn "WARNING: can't load module Net::Libdnet,";
    $HAVE_LIBDNET = 0;
}

# Install Term::ReadLine::Gnu from the CPAN to get history and completion.
use Term::ReadLine;

use Conf;
use Dissectors;
use Field;
use Func;
use Help;
use Layer;
use Packet;

# This piece of code is inspired from the Perl Cookbook (section 10.15).
# It is used here to allow creating objects without using "new",
# e.g. $p=IP() instead of $p=new IP()
# or "Field(...)" instead of "new Field(...)" in the dissectors.
sub AUTOLOAD {
    use vars qw($AUTOLOAD);
    my $protocol = $AUTOLOAD;
    $protocol =~ s/.*:://;
    
    # If "DESTROY" is passed, nothing is returned. This allows doing "print IP()" without error.
    return new $protocol(@_) if $protocol ne "DESTROY";
} 

# Loading global configuration
our $conf = new Conf();

1;
