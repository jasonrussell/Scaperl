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
use Scaperl;

use warnings;
# use strict is not used to allow "$p=IP()" instead of "my $p=IP()" at the prompt

# Welcome :)
my $VERSION = "0.1";
my $welcome = "Welcome to Scaperl ($VERSION) Copyright 2011 Graham Clark, Jason Russell\nCopyright 2006 Sylvain SARMEJEANNE\n. If you're lost, just shout for \"help\".\n";
print $welcome;

# Setting the terminal
my $prompt = "scaperl> ";
my $term_name = "Scaperl";
my $scaperl = new Term::ReadLine($term_name);
$scaperl->ornaments(0);

# Completion for functions and dissectors
our @FUNCTION_LIST = qw(sd sendp str sniff);
our @DISSECTOR_LIST = qw(Ether Dot1Q IP ICMP TCP UDP Raw ClassicBSDLoopback OpenBSDLoopback);

my $attribs = $scaperl->Attribs;
$attribs->{completion_function} = sub {return (@FUNCTION_LIST, @DISSECTOR_LIST);};

# Main loop. This is inspired from the POD page of Term::Readline.
while (defined ($_ = $scaperl->readline($prompt))) {
    eval $_;
    warn $@ if $@;
    print "\n";
}

print "\n";
