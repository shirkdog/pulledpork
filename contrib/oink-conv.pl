#! /usr/bin/perl -w

# simple script to convert oinkmaster conf files to the files that PulledPork understands... 

# non comment lines other than disablesid, enablesid or modifysid go into pp.conf

# I've used this successfully on a couple of large oinkmaster.conf files

# as always ymmv. - Contributed by Russell Fulton

# usage: perl oink-conv.pl oinkmaster.conf

open(DIS, ">disabled.conf") || die "failed to open disabled file"; 
open(EN, ">enabled.conf") || die "failed to open enabled file"; 
open(MOD, ">modified.conf") || die "failed to open modified file"; 
open(PP, ">pp.conf" )|| die "failed to open pp.conf file"; 

while ( <> ) {
    chomp;
    s/^\s+//;
    next if /^#/;
    next if /^$/;
    s/(#.*)$//;   # remove comment
       $comment = $1 || '';
    if( s/^disablesid\s+//i ) {   #disablesid 184, 221, 230, 241, 251, 253, 254, 257

	print DIS "1:", join( ", 1:", split(/\s*,\s*/, $_ ) ), " # $comment\n";
    } elsif( s/^modifysid\s+//i ) {  #  modifysid 2001855  "type limit, count 1, seconds 360" | "type both, count 4, seconds 600"
	my @sids; #  = undef;
	while( s/^(\d+)// ) {
	    push( @sids, $1);
	    s/^\s*,\s*//;
	}
	print MOD "1:", join( ", 1:", @sids ), " $_ # $comment\n";

    } elsif( s/^enablesid\s+//i ) {
	print EN "1:", join( ", 1:", (split(/\s*,\s*/, $_ )) ), " # $comment\n";
    } else {
	print PP "$_\n";
    }
}
