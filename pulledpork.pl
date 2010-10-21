#!/usr/bin/perl

## pulledpork v(whatever it says below!)
## cummingsj@gmail.com

# Copyright (C) 2009-2010 JJ Cummings

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use strict;
use warnings;
use File::Copy;
use LWP::UserAgent;
use HTTP::Request::Common;
use HTTP::Status qw (is_success);
use Crypt::SSLeay;
use Sys::Syslog;
use Digest::MD5;
use File::Path;
use Getopt::Long qw(:config no_ignore_case bundling);
use Archive::Tar;
use POSIX qw(:errno_h);
use Switch;
use Carp;

# we are gonna need these!
my ( $oinkcode, $temp_path, $rule_file , $Syslogging);
my $VERSION = "PulledPork v0.5.0 The Drowning Rat";
my $ua      = LWP::UserAgent->new;

# routine to grab our config from the defined config file
sub parse_config_file {
    my ( $FileConf, $Config_val ) = @_;
    my ( $config_line, $Name, $Value );

    if ( !open( CONFIG, "$FileConf" ) ) {
        print "ERROR: Config file not found : $FileConf\n";
        syslogit( 'err|local0', "FATAL: Config file not found: $FileConf" ) if $Syslogging;
        exit(0);
    }
    open( CONFIG, "$FileConf" );
    while (<CONFIG>) {
        $config_line = $_;
        chomp($config_line);
        $config_line = trim($config_line);
        if ( ( $config_line !~ /^#/ ) && ( $config_line ne "" ) ) {
            ( $Name, $Value ) = split( /=/, $config_line );
            if ( $Value =~ /,/ && $Name eq "rule_url" ) {
                push( @{ $$Config_val{$Name} }, split( /,/, $Value ) );
            }
            elsif ( $Name eq "rule_url" ) {
                push( @{ $$Config_val{$Name} }, split( /,/, $Value ) )
                  if $Value;
            }
            else {
                $$Config_val{$Name} = $Value;
            }
        }
    }

    close(CONFIG);

}

my ( $Verbose, $Hash, $ALogger, $Config_file, $Sorules, $Auto );
my ( $Output, $Distro, $Snort, $Sostubs, $sid_changelog,$ignore_files );
my ( $Snort_config, $Snort_path,  $Textonly,    $grabonly,	  $ips_policy, );
my ( $pid_path,     $SigHup,      $NoDownload,  $sid_msg_map, @base_url );
my ( $local_rules,  $arch, 		  $docs);


$Verbose = 0;
undef($Hash);
undef($ALogger);

my %rules_hash    = ();
my %oldrules_hash = ();
my %sid_msg_map   = ();
my %sidmod 		  = ();
undef %rules_hash;
undef %oldrules_hash;
undef %sid_msg_map;

## Help routine.. display help to stdout then exit
sub Help {
    my $msg = shift;
    if ($msg) { print "\nERROR: $msg\n"; }

    print <<__EOT;
  Usage: $0 [-lvvVdnHTng? -help] -c <config filename> -o <rule output path>
   -O <oinkcode> -s <so_rule output directory> -D <Distro> -S <SnortVer>
   -p <path to your snort binary> -C <path to your snort.conf> -t <sostub output path>
   -h <changelog path> -I (security|connectivity|balanced) -i <path to disablesid.conf>
   -b <path to dropsid.conf> -e <path to enablesid.conf> -M <path to modifysid.conf>
  
   Options:
   -c Where the pulledpork config file lives.
   -i Where the disablesid config file lives.
   -b Where the dropsid config file lives.
   -e Where the enablesid config file lives.
   -M where the modifysid config file lives.
   -o Where do you want me to put generic rules file?
   -r Where do you want me to put the reference files (xxxx.txt)
   -L Where do you want me to read your local.rules for inclusion in sid-msg.map
   -h path to the sid_changelog if you want to keep one?
   -u Where do you want me to pull the rules tarball from 
      (ET, Snort.org, see pulledpork config rule_url option for value ideas)
   -O What is your Oinkcode?
   -I Specify a base ruleset( -I security,connectivity,or balanced, see README.RULESET)
   -T Process text based rules files only, i.e. DO NOT process so_rules
   -m where do you want me to put the sid-msg.map file?
   -s Where do you want me to put the so_rules?
   -S What version of snort are you using (2.8.6 or 2.9.0) are valid values
   -C Path to your snort.conf
   -p Path to your Snort binary
   -t Where do you want me to put the so_rule stub files? ** Thus MUST be uniquely 
      different from the -o option value
   -D What Distro are you running on, for the so_rules
      Valid Distro Types=Debian-Lenny, Ubuntu-6.01.1, Ubuntu-8.04
		CentOS-4.6, Centos-4-8, CentOS-5.0, Centos-5-4
		FC-5, FC-9, FC-11, FC-12, RHEL-5.0
		FreeBSD-6.3, FreeBSD-7-2, FreeBSD-7-3, FreeBSD-7.0, FreeBSD-8-0, FreeBSD-8-1
   -l Log Important Info to Syslog (Errors, Successful run etc, all items logged as WARN or higher) 
   -v Verbose mode, you know.. for troubleshooting and such nonsense.
   -vv EXTRA Verbose mode, you know.. for in-depth troubleshooting and other such nonsense.
   -d Do not verify signature of rules tarball, i.e. downloading fron non VRT or ET locations.
   -H Send a SIGHUP to the pids listed in the config file
   -n Do everything other than download of new files (disablesid, etc)
   -g grabonly (download tarball rule file(s) and do NOT process)
   -V Print Version and exit
   -help/? Print this help info.


__EOT

    exit(0);
}

## OMG We MUST HAVE FLYING PIGS!
sub pulledpork {

    print <<__EOT;

    http://code.google.com/p/pulledpork/
      _____ ____
     `----,\\    )
      `--==\\\\  /    $VERSION
       `--==\\\\/
     .-~~~~-.Y|\\\\_  Copyright (C) 2009-2010 JJ Cummings
  \@_/        /  66\\_  cummingsj\@gmail.com
    |    \\   \\   _(\")
     \\   /-| ||'--'  Rules give me wings!
      \\_\\  \\_\\\\
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

__EOT

}

## initialize some vars
my $rule_digest = "";
my $md5         = "";

## Fly piggy fly!
pulledpork();
if ( $#ARGV == -1 ) {
    Help(
"Please read the README for runtime options and configuration documentation"
    );
}

# subroutine to cleanup the temp rubbish!!!
sub temp_cleanup {
    my $remove = rmtree( $temp_path . "tha_rules" );
    print "Cleanup....\n" if $Verbose;
    print
      "\tremoved $remove temporary snort files or directories from $temp_path"
      . "tha_rules!\n"
      if $Verbose;
}

# subroutine to extract the files to a temp path so that we can do what we need to do..
sub rule_extract {
    my ( $rule_file, $temp_path, $Distro, $arch, $Snort, $Sorules, $ignore, $docs ) =
      @_;
    print "Prepping rules from $rule_file for work....\n";
    print "\textracting contents of $temp_path$rule_file...\n" if $Verbose;
    mkpath( $temp_path . "tha_rules" );
    mkpath( $temp_path . "tha_rules/so_rules" );
    my $tar = Archive::Tar->new();
    $tar->read( $temp_path . $rule_file );
    my @ignores = split( /,/, $ignore );

    foreach (@ignores) {
        print "\tIgnoring: $_.rules from the tarball\n" if $Verbose;
        $tar->remove("rules/$_.rules");
        $tar->remove("preproc_rules/$_.rules");
    }
    my @files = $tar->get_files();
    foreach (@files) {
        my $filename   = $_->name;
        my $singlefile = $filename;
        if ( $filename =~ /^rules\/.*\.rules$/ ) {
            $singlefile =~ s/^rules\///;
            $tar->extract_file( $filename,
                $temp_path . "/tha_rules/" . $singlefile );
            print "\tExtracted: /tha_rules/$singlefile\n" if $Verbose;
        }
        elsif ( $filename =~ /^preproc_rules\/.*\.rules$/ ) {
            $singlefile =~ s/^preproc_rules\///;
            $tar->extract_file( $filename,
                $temp_path . "/tha_rules/" . $singlefile );
            print "\tExtracted: /tha_rules/$singlefile\n" if $Verbose;
        }
        elsif ($Sorules
            && $filename =~
            /^so_rules\/precompiled\/($Distro)\/($arch)\/($Snort)\/.*\.so/
            && -d $Sorules )
        {
            $singlefile =~
              s/^so_rules\/precompiled\/($Distro)\/($arch)\/($Snort)\///;
            $tar->extract_file( $filename, $Sorules . $singlefile );
            print "\tExtracted: $Sorules$singlefile\n" if $Verbose;
        }
        elsif ($docs
            && $filename =~ /^doc\/signatures\/.*\.txt/ && -d $docs )
        {
            $singlefile =~
              s/^doc\/signatures\///;
            $tar->extract_file( $filename, $docs . $singlefile );
            print "\tExtracted: $docs$singlefile\n" if $Verbose == 2;
        }
    }
    if ( !$Verbose ) { print "\tDone!\n"; }
}

# subroutine to actually check the md5 values, if they match we move onto file manipulation routines
sub compare_md5 {
    my (
        $oinkcode, $rule_file, $temp_path,   $Hash,
        $base_url, $md5,       $rule_digest, $Distro,
        $arch,     $Snort,     $Sorules,     $ignore_files,
        $docs
    ) = @_;
    if ( $rule_digest =~ $md5 && !$Hash ) {
        if ($Verbose) {
            print
"\tThe MD5 for $rule_file matched $md5\n\tso I'm not gonna download the rules file again suckas!\n";
        }
        if ( !$Verbose ) { print "\tThey Match\n\tDone!\n"; }
        rule_extract( $rule_file, $temp_path, $Distro, $arch, $Snort, $Sorules,
            $ignore_files, $docs ) if !$grabonly;
    }
    elsif ( !$Hash ) {
        if ($Verbose) {
            print
"\tThe MD5 for $rule_file did not match the latest digest... so I am gonna fetch the latest rules file!\n";
        }
        if ( !$Verbose ) { print "\tNo Match\n\tDone\n"; }
        rulefetch( $oinkcode, $rule_file, $temp_path, $base_url );
        $rule_digest = md5sum( $rule_file, $temp_path );
        compare_md5(
            $oinkcode, $rule_file, $temp_path,   $Hash,
            $base_url, $md5,       $rule_digest, $Distro,
            $arch,     $Snort,     $Sorules,     $ignore_files,
            $docs
        );
    }
    else {
        if ($Verbose) {
            print
"\tOk, not verifying the digest.. lame, but that's what you specified!\n";
            print
"\tSo if the rules tarball doesn't extract properly and this script croaks.. it's your fault!\n";
        }
        if ( !$Verbose ) { print "\tNo Verify Set\n\tDone!\n"; }
        rule_extract( $rule_file, $temp_path, $Distro, $arch, $Snort, $Sorules,
            $ignore_files, $docs ) if !$grabonly;
    }
}

# mimic LWP::Simple getstore routine - Thx pkthound!
sub getstore {
    my ( $url, $file ) = @_;
    my $request = HTTP::Request->new( GET => $url );
    my $response = $ua->request( $request, $file );
    $response->code;
}

## time to grab the real 0xb33f
sub rulefetch {
    my ( $oinkcode, $rule_file, $temp_path, $base_url ) = @_;
    print "Rules tarball download of $rule_file....\n";
    $base_url = slash( 0, $base_url );
    my ($getrules_rule);
    if ($Verbose) {
        print "\tFetching rules file: $rule_file\n";
        if ($Hash) { print "But not verifying MD5\n"; }
    }
    if ( $base_url =~ /snort\.org/i ) {
        $getrules_rule =
          getstore( "https://www.snort.org/reg-rules/$rule_file/$oinkcode",
            $temp_path . $rule_file );
    }
    else {
        $getrules_rule =
          getstore( $base_url . "/" . $rule_file, $temp_path . $rule_file );
    }
    if ( $getrules_rule == 403 ) {
        print
"\tA 403 error occurred, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n",
"\tYou may also wish to verfiy your oinkcode, tarball name, and other configuration options\n";
        syslogit( 'emerg|local0', "FATAL: 403 error occured" ) if $Syslogging;
        exit(1); # For you shirkdog
    }
    elsif ( $getrules_rule == 404 ) {
        print
"\tA 404 error occurred, please verify your filenames and urls for your tarball!\n";
        syslogit( 'emerg|local0', "FATAL: 404 error occured" ) if $Syslogging;
        exit(1); # For you shirkdog
    }
    unless ( is_success($getrules_rule) ) {
        syslogit( 'emerg|local0',
            "FATAL: Error $getrules_rule when fetching $rule_file" ) if $Syslogging;
		croak "\tError $getrules_rule when fetching " . $rule_file;
    }

    if ($Verbose)    { print("\tstoring file at: $temp_path$rule_file\n\n"); }
    if ( !$Verbose ) { "\tDone!\n"; }
}

# subroutine to deterine the md5 digest of the current rules file
sub md5sum {
    my ( $rule_file, $temp_path ) = @_;
    open( MD5FILE, "$temp_path$rule_file" )
      or croak $!;
    binmode(MD5FILE);
    $rule_digest = Digest::MD5->new->addfile(*MD5FILE)->hexdigest;
    close(MD5FILE);
    if ($@) {
        print $@;
        return "";
    }
    if ($Verbose) {
        print "\tcurrent local rules file  digest: $rule_digest\n";
    }
    return $rule_digest;
}

# subroutine to fetch the latest md5 digest signature file from snort.org
sub md5file {
    my ( $oinkcode, $rule_file, $temp_path, $base_url ) = @_;
    my ( $getrules_md5, $md5 );
    $base_url = slash( 0, $base_url );
    print "Checking latest MD5 for $rule_file....\n";
    print "\tFetching md5sum for: " . $rule_file . ".md5\n" if $Verbose;
    if ( $base_url =~ /snort\.org/i ) {
        $getrules_md5 =
          getstore( "https://www.snort.org/reg-rules/$rule_file.md5/$oinkcode",
            $temp_path . $rule_file . ".md5" );
    }
    elsif ( $base_url =~ /emergingthreats\.net/i ) {
        $getrules_md5 = getstore(
            "$base_url/$rule_file" . ".md5",
            $temp_path . $rule_file . ".md5"
        );
    }
    if ( $getrules_md5 == 403 ) {
        print
"\tA 403 error occurred, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n",
"\tYou may also wish to verfiy your oinkcode, tarball name, and other configuration options\n";
    }
    elsif ( $getrules_md5 == 404 ) {
        print
"\tA 404 error occurred, please verify your filenames and urls for your tarball!\n";
    }
    croak "\tError $getrules_md5 when fetching "
      . $base_url . "/"
      . $rule_file . ".md5"
      unless is_success($getrules_md5);
    open( FILE, "$temp_path$rule_file.md5" )
      or croak $!;
    $md5 = <FILE>;
    chomp($md5);
    close(FILE);
    $md5 =~ /\w{32}/
      ; ## Lets just grab the hash out of the string.. don't care about the rest!
    $md5 = $&;
    if ($Verbose) { print "\tmost recent rules file digest: $md5\n"; }
    return $md5;
}

# This replaces the copy_rules routine and allows for in-memory processing
# of disablesid, enablesid, dropsid and other sid functions.. here we place
# all of the rules values into a hash as {$gid}{$sid}=$rule
sub read_rules {
    my ( $hashref, $path, $extra_rules ) = @_;
    my ( $file, $sid, $gid, @elements );
    print "\t" if $Verbose;
    print "Reading rules...\n";
    my @local_rules = split( /,/, $extra_rules );
    foreach (@local_rules) {
        $extra_rules = slash( 0, $_ );
        if ( $extra_rules && -f $extra_rules ) {
            open( DATA, "$extra_rules" )
              || croak "Couldn't read $extra_rules - $!\n";
            my @extra_raw = <DATA>;
            close(DATA);
            my $trk = 0;
            my $record;
            foreach my $row (@extra_raw) {
                $row = trim($row);
                chomp($row);
                if ( $row =~ /^\s*#*\s*(alert|drop|pass)/i ) {
                    if ( ( $row !~ /^#/ ) && ( $row ne "" ) ) {
                        if ( $row =~ /\\$/ ) {
                            $row =~ s/\\$//;
                            $record = $record . $row;
                            $trk    = 1;
                        }
                        elsif ( $row !~ /\\$/ && $trk == 1 ) {
                            $record = $record . $row;
                            if ( $record =~ /sid:\s*\d+/ ) {
                                $sid = $&;
                                $sid =~ s/sid:\s*//;
                                $$hashref{0}{ trim($sid) }{'rule'} = $record;
                            }
                            $trk = 0;
                        }
                        else {
                            if ( $row =~ /sid:\s*\d+/ ) {
                                $sid = $&;
                                $sid =~ s/sid:\s*//;
                                $$hashref{0}{ trim($sid) }{'rule'} = $row;
                            }
                            $trk = 0;
                        }
                    }
                }
            }
            undef @extra_raw;
        }
    }
    if ( -d $path ) {
        opendir( DIR, "$path" );
        while ( defined( $file = readdir DIR ) ) {
            open( DATA, "$path$file" ) || croak "Couldn't read $file - $!\n";
            @elements = <DATA>;
            close(DATA);

            foreach my $rule (@elements) {
                chomp($rule);
                $rule = trim($rule);
                if ( $rule =~ /^\s*#*\s*(alert|drop|pass)/i ) {

                    if ( $rule =~ /sid:\s*\d+/i ) {
                        $sid = $&;
                        $sid =~ s/sid:\s*//;
                        if ( $rule =~ /gid:\s*\d+/i ) {
                            $gid = $&;
                            $gid =~ s/gid:\s*//;
                        }
                        else { $gid = 1; }
                        if ( $rule =~ /flowbits:\s*(un)?set/i ) {

# There is a much cleaner way to do this, I just don't have the time to do it right now!
                            my ( $header, $options ) =
                              split( /^[^"]* \(/, $rule );
                            my @optarray = split( /;(\t|\s)?/, $options )
                              if $options;
                            foreach my $option ( reverse(@optarray) ) {
                                my ( $kw, $arg ) = split( /:/, $option )
                                  if $option;
                                next
                                  unless ( $kw && $arg && $kw eq "flowbits" );
                                my ( $flowact, $flowbit ) = split( /,/, $arg );
                                next unless $flowact =~ /(un)?set/i;
                                $$hashref{ trim($gid) }{ trim($sid) }
                                  { trim($flowbit) } = 1;
                            }

                        }
                        $$hashref{ trim($gid) }{ trim($sid) }{'rule'} = $rule;
                        $file =~ s/\.rules//;
                        $$hashref{ trim($gid) }{ trim($sid) }{$file} = 1;
                    }
                }
            }
        }
        close(DIR);
    }
    elsif ( -f $path ) {
        open( DATA, "$path" ) || croak "Couldn't read $path - $!";
        @elements = <DATA>;
        close(DATA);

        foreach my $rule (@elements) {
            if ( $rule =~ /^\s*#*\s*(alert|drop|pass)/i ) {
                if ( $rule =~ /sid:\s*\d+/ ) {
                    $sid = $&;
                    $sid =~ s/sid:\s*//;
                    if ( $rule =~ /gid:\s*\d+/i ) {
                        $gid = $&;
                        $gid =~ s/gid:\s*//;
                    }
                    else { $gid = 1; }
                    if ( $rule =~ /flowbits:\s*(un)?set/ ) {
                        my ( $header, $options ) = split( /^[^"]* \(/, $rule );

# There is a much cleaner way to do this, I just don't have the time to do it right now!
                        my @optarray = split( /;(\t|\s)?/, $options )
                          if $options;
                        foreach my $option ( reverse(@optarray) ) {
                            my ( $kw, $arg ) = split( /:/, $option ) if $option;
                            next unless ( $kw && $arg && $kw eq "flowbits" );
                            my ( $flowact, $flowbit ) = split( /,/, $arg );
                            next unless $flowact =~ /(un)?set/i;
                            $$hashref{ trim($gid) }{ trim($sid) }
                              { trim($flowbit) } = 1;
                        }

                    }
                    $$hashref{ trim($gid) }{ trim($sid) }{'rule'} = $rule;
                }
            }
        }
    }
    undef @elements;
}

# sub to generate stub files using the snort --dump-dynamic-rules option
sub gen_stubs {
    my ( $Snort_path, $Snort_config, $Sostubs ) = @_;
    print "Generating Stub Rules....\n";
    unless ( -B $Snort_path ) {
        Help("$Snort_path is not a valid binary file");
    }
    if ( -d $Sostubs && -B $Snort_path && -f $Snort_config ) {
        if ($Verbose) {
            print(
"\tGenerating shared object stubs via:$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs\n"
            );
        }
        open( FH,
            "$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs 2>&1|"
        );
        while (<FH>) {
            print "\t$_" if $_ =~ /Dumping/i && $Verbose;
            next unless $_ =~ /(err|warn|fail)/i;
            syslogit( 'warning|local0', "FATAL: An error occured: $_" ) if $Syslogging;
            print "\tAn error occurred: $_\n";
        }
        close(FH);
    }
    else {
        print(
"Something failed in the gen_stubs sub, please verify your shared object config!\n"
        );
        if ($Verbose) {
            unless ( -d $Sostubs ) {
                Help(
"The path that you specified: $Sostubs does not exist! Please verify your configuration.\n"
                );
            }
            unless ( -f $Snort_path ) {
                Help(
"The file that you specified: $Snort_path does not exist! Please verify your configuration.\n"
                );
            }
            unless ( -f $Snort_config ) {
                Help(
"The file that you specified: $Snort_config does not exist! Please verify your configuration.\n"
                );
            }
        }
    }
    print "\tDone\n";
}

sub vrt_policy {
    my ( $ids_policy, $rule ) = @_;
    my ( $gid, $sid );
    if ( $rule =~ /policy\s$ids_policy/i && $rule !~ /flowbits:noalert/i ) {
        $rule =~ s/^#*\s*//;
    }
    elsif ( $rule !~ /^\s*#/ ) {
        $rule = "# $rule";
    }
    return $rule;
}

sub policy_set {
    my ( $ids_policy, $hashref ) = @_;
    if ($hashref) {
        if ( $ids_policy ne "Disabled" && $ids_policy ne "" ) {
            print "Activating $ids_policy rulesets....\n";
            foreach my $k ( sort keys %$hashref ) {
                foreach my $k2 ( keys %{ $$hashref{$k} } ) {
                    $$hashref{$k}{$k2}{'rule'} =
                      vrt_policy( $ids_policy, $$hashref{$k}{$k2}{'rule'} );
                }
            }

            print "\tDone\n";
        }
    }
}

# this allows the user to use regular expressions to modify rule contents
sub modify_sid {
    my ( $href, $file ) = @_;
    my @arry;
    print "Modifying Sids....\n";
    open( FH, "<$file" ) || carp "Unable to open $file\n";
    while (<FH>) {
        next if ( ( $_ =~ /^\s*#/ ) || ( $_ eq " " ) );
        if ( $_ =~ /([\d+|,|\*]*)\s+"(.+)"\s+"(.+)"/ ) {
            my ( $sids, $from, $to ) = ( $1, $2, $3 );
            @arry = split( /,/, $sids ) if $sids !~ /\*/;
            @arry = "*" if $sids =~ /\*/;
            foreach my $sid (@arry) {
                $sid = trim($sid);
                if ( $sid ne "*" && exists $$href{1}{$sid} ) {
                    print "\tModifying SID:$sid from:$from to:$to\n"
                      if $Verbose;
                    $$href{1}{$sid}{'rule'} =~ s/$from/$to/
                      if $$href{1}{$sid}{'rule'} !~ /^\s*#/;
                }
                elsif ( $sid eq "*" ) {
                    print "\tModifying ALL SIDS from:$from to:$to\n"
                      if $Verbose;
                    foreach my $k ( sort keys %{ $$href{1} } ) {
                        $$href{1}{$k}{'rule'} =~ s/$from/$to/;
                    }
                }
            }
            undef @arry;
        }
    }
    print "\tDONE\n";
    close(FH);
}

# this relaces the enablesid, disablesid and dropsid functions..
# speed ftw!
sub modify_state {
    my ( $function, $SID_conf, $hashref ) = @_;
    my ( @sid_mod, $sidlist );
    print "Processing $SID_conf....\n";
    if ( -f $SID_conf ) {
        open( DATA, "$SID_conf" ) or carp "unable to open $SID_conf $!";
        while (<DATA>) {
            $sidlist = $_;
            chomp($sidlist);
            $sidlist = trim($sidlist);
            if ( ( $sidlist !~ /^\s*#/ ) && ( $sidlist ne "" ) && !(@sid_mod) )
            {
                @sid_mod = split( /,/, $sidlist );
            }
            elsif ( ( $sidlist !~ /^\s*#/ ) && ( $sidlist ne "" && @sid_mod ) )
            {
                push( @sid_mod, split( /,/, $sidlist ) );
            }
        }
        close(DATA);
        if ($hashref) {
            my $sidcount = 0;
            foreach (@sid_mod) {
                if ( $_ =~ /^(\d+):\d+-\1:\d+/ ) {
                    my ( $lsid, $usid ) = split( /-/, $& );
                    my $gid = $lsid;
                    $sid_mod[$sidcount] = $lsid;
                    $gid  =~ s/:\d+//;
                    $lsid =~ s/\d+://;
                    $usid =~ s/\d+://;
                    while ( $lsid < $usid ) {
                        $lsid++;
                        push( @sid_mod, $gid . ':' . $lsid );
                    }
                }
                elsif ( $_ =~ /^pcre\:.+/i ) {
                    my ( $pcre, $regex ) = split( /\:/, $& );
                    foreach my $k1 ( keys %$hashref ) {
                        foreach my $k2 ( keys %{ $$hashref{$k1} } ) {
                            next unless defined $$hashref{$k1}{$k2}{'rule'};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2
                              if (
                                ( $$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i )
                                && ( $sid_mod[$sidcount] =~ /[a-xA-X](\w|\W)*/ )
                              );
                            push( @sid_mod, $k1 . ":" . $k2 )
                              if (
                                ( $$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i )
                                && ( $sid_mod[$sidcount] =~ /\d+:\d+/ ) );
                        }
                    }
                }
                elsif ( $_ =~ /^[a-xA-X]+\:.+/ ) {
                    my $regex = $&;
                    $regex =~ s/\:/,/;
                    foreach my $k1 ( keys %$hashref ) {
                        foreach my $k2 ( keys %{ $$hashref{$k1} } ) {
                            next unless defined $$hashref{$k1}{$k2}{'rule'};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2
                              if (
                                ( $$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i )
                                && ( $sid_mod[$sidcount] =~ /[a-xA-X](\w|\W)*/ )
                              );
                            push( @sid_mod, $k1 . ":" . $k2 )
                              if (
                                ( $$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i )
                                && ( $sid_mod[$sidcount] =~ /\d+:\d+/ ) );
                        }
                    }
                }
                elsif ( $_ =~ /^MS\d+-.+/i ) {
                    my $regex = $&;
                    foreach my $k1 ( keys %$hashref ) {
                        foreach my $k2 ( keys %{ $$hashref{$k1} } ) {
                            next unless defined $$hashref{$k1}{$k2}{'rule'};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2
                              if (
                                ( $$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i )
                                && ( $sid_mod[$sidcount] =~ /[a-xA-X](\w|\W)*/ )
                              );
                            push( @sid_mod, $k1 . ":" . $k2 )
                              if (
                                ( $$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i )
                                && ( $sid_mod[$sidcount] =~ /\d+:\d+/ ) );
                        }
                    }
                }
                elsif ( $_ =~ /[a-xA-X]+(-|\w)*/ ) {
                    my $category = $&;
                    foreach my $k1 ( keys %$hashref ) {
                        foreach my $k2 ( keys %{ $$hashref{$k1} } ) {
                            next unless defined $$hashref{$k1}{$k2}{$category};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2;
                            push( @sid_mod, $k1 . ":" . $k2 )
                              if $sid_mod[$sidcount] =~ /\d+:\d+/;
                        }
                    }
                }
                $sidcount++;
            }
            $sidcount = 0;
            foreach (@sid_mod) {
                if ( $_ =~ /^\d+:\d+/ ) {
                    my $gid = $&;
                    my $sid = $gid;
                    if ( $gid && $sid ) {
                        $gid =~ s/:\d+//;
                        $sid =~ s/\d+://;
                        switch ($function) {
                            case "enable" {
                                if ( exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'} =~
                                    /^\s*#\s*(alert|drop|pass)/i )
                                {
                                    $$hashref{$gid}{$sid}{'rule'} =~
                                      s/^\s*#+\s*//;
                                    if ($Verbose) {
                                        print "\tEnabled $gid:$sid\n";
                                    }
                                    $sidcount++;
                                }
                            }
                            case "drop" {
                                if ( exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'} =~
                                    /^\s*#*\s*alert/i )
                                {
                                    $$hashref{$gid}{$sid}{'rule'} =~
                                      s/^\s*#*\s*//;
                                    $$hashref{$gid}{$sid}{'rule'} =~
                                      s/^alert/drop/;
                                    if ($Verbose) {
                                        print "\tWill drop $gid:$sid\n";
                                    }
                                    $sidcount++;
                                }
                            }
                            case "disable" {
                                if ( exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'} =~
                                    /^\s*(alert|drop|pass)/i )
                                {
                                    $$hashref{$gid}{$sid}{'rule'} =
                                      "# " . $$hashref{$gid}{$sid}{'rule'};
                                    if ($Verbose) {
                                        print "\tDisabled $gid:$sid\n";
                                    }
                                    $sidcount++;
                                }
                            }
                        }
                    }
                }
            }
            print "\tModified $sidcount rules\n";
        }
    }
    print "\tDone\n";
    undef @sid_mod;
}

sub sig_hup {
    my ($pidlist) = @_;
    my @pids = split( /,/, $pidlist );
    my $pid;
    print "HangUP Time....\n";
    foreach $pid (@pids) {
        open( FILE, "$pid" )
          or croak $!;
        my $realpid = <FILE>;
        chomp($realpid);
        close(FILE);
        my $hupres = kill 1, $realpid;
        if ($Verbose) {
            print
              "\tSent kill signal to $realpid from $pid with result $hupres\n";
        }
    }
    if ( !$Verbose ) { print "\tDone!\n"; }
    undef @pids;
}

sub sid_msg {
    my ( $ruleshash, $sidhash ) = @_;
    my ( $gid, $arg, $msg );
    print "Generating sid-msg.map....\n";
    foreach my $k ( sort keys %$ruleshash ) {
        foreach my $k2 ( sort keys %{ $$ruleshash{$k} } ) {
            ( my $header, my $options ) =
              split( /^[^"]* \(/, $$ruleshash{$k}{$k2}{'rule'} )
              if defined $$ruleshash{$k}{$k2}{'rule'};
            my @optarray = split( /;(\t|\s)?/, $options ) if $options;
            foreach my $option ( reverse(@optarray) ) {
                my ( $kw, $arg ) = split( /:/, $option ) if $option;
                if ( $kw && $arg ) {
                    if ( $kw eq "gid" ) {
                        $gid = $arg;
                    }
                    elsif ( $kw eq "reference" ) {
                        push( @{ $$sidhash{"$k2"}{"refs"} }, $arg ) if $arg;
                    }
                    elsif ( $kw eq "msg" ) {
                        $arg =~ s/"//g;
                        $msg = $arg;
                    }
                }
            }
            if ($gid) {
                $$sidhash{$k2}{'gid'} = $gid;
            }
            else {
                $$sidhash{$k2}{'gid'} = "1";
            }
            $$sidhash{$k2}{'msg'} = $msg unless defined $$sidhash{$k2}{'msg'};
            undef @optarray;
        }
    }
    print "\tDone\n";
}

sub rule_write {
    my ( $hashref, $file, $gid ) = @_;
    print "Writing $file....\n";
    open( WRITE, ">$file" ) || croak "Unable to write $file - $!\n";
    if ( $gid == 1 ) {
        foreach my $k ( sort keys %$hashref ) {
            foreach my $k2 ( sort keys %{ $$hashref{$k} } ) {
                next unless defined $$hashref{$k}{$k2}{'rule'};
                print WRITE $$hashref{$k}{$k2}{'rule'} . "\n"
                  if ( $k ne 0 ) && ( $k ne 3 );
            }
        }
    }
    elsif ( $gid == 3 ) {
        foreach my $k2 ( sort keys %{ $$hashref{$gid} } ) {
            next unless defined $$hashref{$gid}{$k2}{'rule'};
            print WRITE $$hashref{$gid}{$k2}{'rule'} . "\n";
        }
    }
    close(WRITE);
    print "\tDone\n";
}

sub sid_write {
    my ( $hashref, $file ) = @_;
    print "Writing $file....\n";
    open( WRITE, ">$file" ) || croak "Unable to write $file -$!";
    foreach my $k ( sort keys %$hashref ) {
        next unless defined $$hashref{$k}{'msg'};
        print WRITE $k . " || " . $$hashref{$k}{'msg'};
        foreach ( @{ $$hashref{$k}{'refs'} } ) {
            print WRITE " || " . $_;
        }
        print WRITE "\n";
    }
    close(WRITE);
    print "\tDone\n";
}

sub flowbit_check {
    my ( $rule, $aref ) = @_;
    my ( $header, $options ) = split( /^[^"]* \(/, $rule );
    my @optarray = split( /;(\t|\s)?/, $options ) if $options;
    foreach my $option ( reverse(@optarray) ) {
        my ( $kw, $arg ) = split( /:/, $option ) if $option;
        next unless ( $kw && $arg && $kw eq "flowbits" );
        my ( $flowact, $flowbit ) = split( /,/, $arg );
        next unless $flowact =~ /is(not)?set/i;
        push( @$aref, $flowbit );
    }
}

sub flowbit_set {
    my $href    = shift;
    my $counter = 0;
    my @flowbits;
    foreach my $k1 ( keys %$href ) {
        foreach my $k2 ( keys %{ $$href{$k1} } ) {
            next unless $$href{$k1}{$k2}{'rule'} =~ /^\s*(alert|drop|pass)/;
            next
              unless $$href{$k1}{$k2}{'rule'} =~
                  /flowbits:\s*is(not)?set\s*,\s*(\w|\.|\-|_)+/i;
            flowbit_check( $$href{$k1}{$k2}{'rule'}, \@flowbits );
        }
    }
    my %dups;
    map { $dups{$_} = 1 } @flowbits;
    @flowbits = keys %dups;
    undef %dups;
    foreach my $k1 ( keys %$href ) {
        foreach my $k2 ( keys %{ $$href{$k1} } ) {
            foreach my $flowbit (@flowbits) {
                next
                  unless defined $$href{$k1}{$k2}{$flowbit}
                      && $$href{$k1}{$k2}{'rule'} =~
                      /^\s*#\s*(alert|drop|pass)/i;
                $$href{$k1}{$k2}{'rule'} =~ s/^\s*#\s*//;
                $counter++;
            }
        }
    }
    undef @flowbits;
    print "\tEnabled $counter flowbits\n" if $counter > 0;
    return $counter;
}

sub changelog {
    my ( $changelog, $hashref, $hashref2, $ips_policy ) = @_;

    print "Writing $changelog....\n";
    my ( @newsids, @delsids );
    undef @newsids;
    undef @delsids;
    my $rt       = 0;
    my $dt       = 0;
    my $dropped  = 0;
    my $enabled  = 0;
    my $disabled = 0;
    foreach my $k1 ( keys %rules_hash ) {

        foreach my $k2 ( keys %{ $$hashref{$k1} } ) {
            push( @newsids, $k1 . ":" . $k2 )
              unless defined $$hashref2{$k1}{$k2}{'rule'};
            $rt++ unless defined $$hashref2{$k1}{$k2}{'rule'};
            next  unless defined $$hashref{$k1}{$k2}{'rule'};
            if ( $$hashref{$k1}{$k2}{'rule'} =~ /^\s*(alert|pass)/ ) {
                $enabled++;
            }
            elsif ( $$hashref{$k1}{$k2}{'rule'} =~ /^\s*drop/ ) {
                $dropped++;
            }
            elsif (
                $$hashref{$k1}{$k2}{'rule'} =~ /^\s*#*\s*(alert|drop|pass)/ )
            {
                $disabled++;
            }
        }
    }
    foreach my $k1 ( sort keys %$hashref2 ) {
        for my $k2 ( sort keys %{ $$hashref2{$k1} } ) {
            next if defined $$hashref{$k1}{$k2}{'rule'};
            push( @delsids, $k1 . ":" . $k2 );
            $dt++;
        }
    }
    if ( -f $changelog ) {
        open( WRITE, ">>$changelog" ) || croak "$changelog $!\n";
    }
    else {
        open( WRITE, ">$changelog" ) || croak "$changelog $!\n";
        print WRITE
          "-=BEGIN PULLEDPORK SNORT RULES CHANGELOG, Tracking started on "
          . gmtime(time)
          . " GMT=-\n\n\n";
    }
    print WRITE "\n-=Begin Changes Logged for " . gmtime(time) . " GMT=-\n";
    print WRITE "\nNew Rules\n" if @newsids;
    foreach (@newsids) { print WRITE "\t" . $_ . "\n"; }
    print WRITE "\nDeleted Rules\n" if @delsids;
    foreach (@delsids) { print WRITE "\t" . $_ . "\n"; }
    print WRITE "\nSet Policy: $ips_policy\n" if $ips_policy;
    print WRITE "\nRule Totals\n";
    print WRITE "\tNew:-------$rt\n";
    print WRITE "\tDeleted:---$dt\n";
    print WRITE "\tEnabled:---$enabled\n";
    print WRITE "\tDropped:---$dropped\n";
    print WRITE "\tDisabled:--$disabled\n";
    print WRITE "\tTotal:-----" . ( $enabled + $disabled + $dropped ) . "\n";
    print WRITE "\n-=End Changes Logged for " . gmtime(time) . " GMT=-\n";
    close(WRITE);
    print "\tDone\n";

    print "Rule Stats....\n";
    print "\tNew:-------$rt\n";
    print "\tDeleted:---$dt\n";
    print "\tEnabled Rules:----$enabled\n";
    print "\tDropped Rules:----$dropped\n";
    print "\tDisabled Rules:---$disabled\n";
    print "\tTotal Rules:------"
      . ( $enabled + $dropped + $disabled )
      . "\n\tDone\n";
    print "Please review $sid_changelog for additional details\n"
      if $sid_changelog;
    undef @newsids;
    undef @delsids;

}

sub trim {
    my ($trimmer) = @_;
    if ($trimmer) {
        $trimmer =~ s/^\s*//;
        $trimmer =~ s/\s*$//;
        return $trimmer;
    }
}

sub slash {
    my ( $operation, $string ) = @_;
    if ( $operation == 0 && $string =~ /\/$/ && $string ne "" ) {
        $string =~ s/\/$//;
    }
    elsif ( $operation == 1 && $string !~ /\/$/ && $string ne "" ) {
        $string = $string . "/";
    }
    return $string;
}

sub Version {
    print("$VERSION\n\n");
    exit(0);
}

sub snort_version {
    my $cmd = shift;
    $cmd .= " -V";
    my $version;
    open( FH, "$cmd 2>&1 |" );
    while (<FH>) {
        next unless $_ =~ /Version/;
        if ( $_ =~ /\d\.\d\.\d\.\d/ ) {
            $version = $&;
        }
        elsif ( $_ =~ /\d\.\d\.\d/ ) {
            $version = $& . ".0";
        }
    }
    close(FH);
    return $version;
}

sub get_arch {
    my $cmd = "uname -a";
    open( FH, "$cmd |" );
    my $arch;
    while (<FH>) {
        next unless $_ =~ /(i386|x86-64|x86_64|i686)/i;
        $arch = $&;
        $arch =~ s/_/-/;
        $arch =~ s/i686/i386/;
    }
    close(FH);
    return $arch;
}

# log to syslog
sub syslogit {
    my ( $level, $msg ) = @_;

    openlog( 'pulledpork', 'ndelay,pid', 'local0' );
    syslog( $level, $msg );
    closelog;
}

## Lets grab any runtime values and insert into our variables using getopt::long
GetOptions(
    "v+"     => \$Verbose,
    "V!"     => sub { Version() },
    "d!"     => \$Hash,
    "l!"     => \$Syslogging,
    "a!"     => \$Auto,
    "T!"     => \$Textonly,
    "H!"     => \$SigHup,
    "n!"     => \$NoDownload,
    "g!"	 => \$grabonly,
    "h=s"    => \$sid_changelog,
    "M=s"    => \$sidmod{modify},
    "L=s"    => \$local_rules,
    "s=s"    => \$Sorules,
    "t=s"    => \$Sostubs,
    "r=s" 	 => \$docs,
    "p=s"    => \$Snort_path,
    "m=s"    => \$sid_msg_map,
    "D=s"    => \$Distro,
    "c=s"    => \$Config_file,
    "i=s"	 => \$sidmod{disable},
    "e=s"    => \$sidmod{enable},
    "I=s"    => \$ips_policy,
    "b=s"	 => \$sidmod{drop},
    "S=s"    => \$Snort,
    "C=s"    => \$Snort_config,
    "o=s"    => \$Output,
    "u=s"    => \@base_url,
    "help|?" => sub { Help() }
);

# Dump our variables for verbose/debug output

if ( !$Config_file ) { Help("No configuration file specified"); }

if ($Verbose) {
    print "Command Line Variable Debug:\n";
    if ($Config_file) { print "\tConfig Path is: $Config_file\n"; }
    if ($rule_file)   { print "\tRule File is: $rule_file\n"; }
    if (@base_url)    { print "\tBase URL is: @base_url\n"; }
    if ($Output)      { print "\tRules file is: $Output\n"; }
    if ($local_rules) { print "\tlocal.rules path is: $local_rules\n"; }
    if ($Sorules)     { print "\tSO Output Path is: $Sorules\n"; }
    if ($Sostubs)     { print "\tSO Stub File is: $Sostubs\n"; }
    if ($docs)		  { print "\tDocs Reference Location is: $docs\n"; }
    if ($sid_msg_map) { print "\tsid-msg.map Output Path is: $sid_msg_map\n"; }
    if ($sid_changelog) {
        print "\tsid changes will be logged to: $sid_changelog\n";
    }
    if ($ips_policy)     { print "\t$ips_policy policy specified\n"; }
    if ($Snort)          { print "\tSnort Version is: $Snort\n"; }
    if ($Snort_path)     { print "\tSnort Path is: $Snort_path\n"; }
    if ($Snort_config)   { print "\tSnort Config File: $Snort_config\n"; }
    if ($sidmod{disable}){ print "\tPath to disablesid file: $sidmod{disable}\n"; }
    if ($sidmod{drop})   { print "\tPath to dropsid file: $sidmod{drop}\n"; }
    if ($sidmod{enable})    { print "\tPath to enablesid file: $sidmod{enable}\n"; }
    if ($sidmod{modify})      { print "\tPath to modifysid file: $sidmod{modify}\n"; }
    if ($Distro)         { print "\tDistro Def is: $Distro\n"; }
    if ($arch)           { print "\tarch Def is: $arch\n"; }
    if ($Verbose)        { print "\tVerbose Flag is Set\n"; }
    if ( $Verbose == 2 ) { print "\tExtra Verbose Flag is Set\n"; }
    if ($Syslogging)     { print "\tLogging Flag is Set\n"; }
    if ($Textonly)       { print "\tText Rules only Flag is Set\n"; }
    if ($SigHup)         { print "\tSIGHUP Flag is Set\n"; }
    if ($NoDownload)     { print "\tNo Download Flag is Set\n"; }
    if ($grabonly)		 { print "\tgrabonly Flag is Set, only gonna download!"; }

    if ($Hash) {
        print
"\tNo MD5 Flag is Set, uhm, ok? I'm gonna fetch the latest file no matter what!\n";
    }
}

# Call the subroutine to fetch config values
my ($Config_key);
my %Config_info = ();
parse_config_file( $Config_file, \%Config_info );

if ($Verbose) {
    print "Config File Variable Debug $Config_file\n";
    foreach $Config_key ( keys %Config_info ) {
        if ( $Config_info{$Config_key} ) {
            print "\t$Config_key = $Config_info{$Config_key}\n";
        }
    }

}

if ( exists $Config_info{'version'} ) {
    croak "You are not using the current version of pulledpork.conf!\n",
      "Please use the version that shipped with $VERSION!\n\n"
      if $Config_info{'version'} ne "0.5.0";
}
else {
    croak
"You are not using the current version of pulledpork.conf!\nPlease use the version that shipped with $VERSION!\n\n";
}

# Check to see if we have command line inputs, if so, they super-seed any config file values!
# We also begin sub execution here

$pid_path     = ( $Config_info{'pid_path'} ) if exists $Config_info{'pid_path'};
$ignore_files = ( $Config_info{'ignore'} )   if exists $Config_info{'ignore'};

if ( !$ips_policy && defined $Config_info{'ips_policy'} ) {
    $ips_policy = $Config_info{'ips_policy'};
}

if ( !$sidmod{enable} && defined $Config_info{'enablesid'} ) {
    $sidmod{enable} = $Config_info{'enablesid'};
}

if ( !$sidmod{modify} && defined $Config_info{'modifysid'} ) {
    $sidmod{modify} = $Config_info{'modifysid'};
}

if ( !$sidmod{drop} && defined $Config_info{'dropsid'} ) {
    $sidmod{drop} = $Config_info{'dropsid'};
}

if ( !$sidmod{disable} && defined $Config_info{'disablesid'} ) {
    $sidmod{disable} = $Config_info{'disablesid'};
}

my @sidact = ('enable','drop','disable');

if ( defined $Config_info{'state_order'} ) {
	(@sidact) = split(/,/,$Config_info{'state_order'});
}

if ( !@base_url ) {
    @base_url = @{ $Config_info{'rule_url'} };
    if ( !@base_url ) {
        Help(
"You need to specify one rule_url at a minimum to fetch the rules files from!\n"
        );
    }
}

if ( !$Output ) {
    $Output = ( $Config_info{'rule_path'} );
    if ( !$Output ) { Help("You need to specify an output rules file!"); }
}
$Output = slash( 0, $Output );

if ( !$Sorules ) {
    $Sorules = ( $Config_info{'sorule_path'} );
}
$Sorules = slash( 1, $Sorules ) if $Sorules;

if ( !$docs ) {
	$docs = ( $Config_info{'docs'} );
}

if ( !$Sostubs ) {
    $Sostubs = ( $Config_info{'sostub_path'} );
}
$Sostubs = slash( 0, $Sostubs ) if $Sostubs;

if ( !$Distro ) {
    $Distro = ( $Config_info{'distro'} );
}

if ( !$Snort ) {
    $Snort = ( $Config_info{'snort_version'} );
}

if ( !$Snort_path ) {
    $Snort_path = ( $Config_info{'snort_path'} );
    $Snort      = snort_version($Snort_path) if ( -B $Snort_path && !$Snort );
    $arch       = get_arch();
    $Textonly   = 1 unless $Snort;
}

if ( !$local_rules && ( $Config_info{'local_rules'} ) ) {
    $local_rules = ( $Config_info{'local_rules'} );
}
elsif ( !$local_rules && !( $Config_info{'local_rules'} ) ) {
    $local_rules = 0;
}

if ( !$Snort_config ) {
    $Snort_config = ( $Config_info{'config_path'} );
}

if ( !$sid_msg_map ) {
    $sid_msg_map = ( $Config_info{'sid_msg'} );
}
if ( !$sid_changelog ) {
    $sid_changelog = ( $Config_info{'sid_changelog'} );
}

if ( !$ips_policy ) {
    $ips_policy = "Disabled";
}

# We need a temp path to work with the files while we do magics on them.. make sure you have plenty
# of space in this path.. ~200mb is a good starting point
$temp_path = ( $Config_info{'temp_path'} );
if ( !$temp_path ) {
    Help("You need to specify a valid temp path, check permissions too!");
}
$temp_path = slash( 1, $temp_path );
if ( !-d $temp_path ) {
    Help("Temporary file path $temp_path does not exist.\n");
}

# set some UserAgent and other connection configs
$ua->agent("$VERSION");
$ua->show_progress(1) if $Verbose;

# New Settings to allow proxy connections to use proper SSL formating - Thx pkthound!
$ua->timeout(15);
$ua->cookie_jar( {} );
$ua->protocols_allowed( [ 'http', 'https' ] );
my $proxy = $ENV{http_proxy};
if ($proxy) {
    $ua->proxy( ['http'], $proxy );
    $proxy = $ENV{https_proxy};
    $ENV{HTTPS_PROXY} = $proxy;
}
if ( $Verbose == 2 ) {
    $ENV{HTTPS_DEBUG} = 1;
    print "\n\nMY HTTPS PROXY = " . $proxy . "\n" if $proxy;
}

# let's fetch the most recent md5 file then compare and do our foo
if ( @base_url && -d $temp_path ) {

    if ( -d $temp_path . "tha_rules" ) {
        print
"\tdoh, we need to perform some cleanup... an unclean run last time?\n"
          if $Verbose;
        temp_cleanup($temp_path);
    }

    if ( !$NoDownload ) {

        foreach (@base_url) {

            undef $Sostubs if ( $Textonly || ( $_ =~ /emergingthreats/ ) );
            my ( $base_url, $rule_file, $oinkcode ) = split( /\|/, $_ );
            croak
"You need to define an oinkcode, please review the rule_url section of the pulledpork config file!\n"
              unless $oinkcode;
            croak(
                "please define the rule_url correctly in the pulledpork.conf\n")
              unless defined $base_url;
            croak(
                "please define the rule_url correctly in the pulledpork.conf\n")
              unless defined $rule_file;

            if ( $base_url =~ /snort\.org/i ) {
                unless ( $rule_file =~ /snortrules-snapshot-\d{4}\.tar\.gz/ ) {
                    croak(
"The specified Snort binary does not exist!\nPlease correct the value or specify the FULL",
                        " rules tarball name in the pulledpork.conf!\n"
                    ) unless $Snort;
                    my $Snortv = $Snort;
                    $Snortv =~ s/\.//g;
                    $rule_file = "snortrules-snapshot-$Snortv.tar.gz";
                }
            }
            elsif ( $base_url =~ /emergingthreats.net/ ) {
                my $Snortv = $Snort;
                $Snortv =~ s/(?<=\d\.\d\.\d)\.\d//;
                $base_url .= "$oinkcode/snort-$Snortv/";
                $Textonly = 1;
            }

            $Hash = 1 unless $base_url =~ /(emergingthreats|snort.org)/;

            if ( !$Hash ) {
                $md5 = md5file( $oinkcode, $rule_file, $temp_path, $base_url );
            }

      # and now lets determine the md5 of the last saved rules file if it exists
            if ( -f "$temp_path" . "$rule_file" && !$Hash ) {
                $rule_digest = md5sum( $rule_file, $temp_path );
            }
            else {    # the file didn't exsist so lets get it
                rulefetch( $oinkcode, $rule_file, $temp_path, $base_url );
                if ( -f "$temp_path" . "$rule_file" && !$Hash ) {
                    $rule_digest = md5sum( $rule_file, $temp_path );
                }
            }

# compare the online current md5 against against the md5 of the rules file on system
            compare_md5(
                $oinkcode, $rule_file, $temp_path,   $Hash,
                $base_url, $md5,       $rule_digest, $Distro,
                $arch,     $Snort,     $Sorules,     $ignore_files,
                $docs
            );
        }
    }
    if ($NoDownload && !$grabonly) {
        foreach (@base_url) {
            my ( $base_url, $rule_file ) = split( /\|/, $_ );
            if ( $base_url =~ /snort\.org/i ) {
                unless ( $rule_file =~ /snortrules-snapshot-\d{4}\.tar\.gz/ ) {
                    croak(
"The specified Snort rules tarball does not exist!\nPlease correct the value or specify the FULL",
                        " rules tarball name in the pulledpork.conf!\n"
                    ) unless $Snort;
                    my $Snortv = $Snort;
                    $Snortv =~ s/\.//g;
                    $rule_file = "snortrules-snapshot-$Snortv.tar.gz";
                }
            }
            croak "file $temp_path/$rule_file does not exist!\n"
              unless -f "$temp_path/$rule_file";
            rule_extract( $rule_file, $temp_path, $Distro, $arch, $Snort,
                $Sorules, $ignore_files, $docs ) if !$grabonly;
        }
    }
    if ($Output && !$grabonly) {
        read_rules( \%rules_hash, "$temp_path" . "tha_rules/", $local_rules );
    }
	if ( $Sorules && $Distro && $Snort && !$Textonly && !$grabonly) {
		gen_stubs( $Snort_path, $Snort_config,
			"$temp_path" . "tha_rules/so_rules/" );
		read_rules( \%rules_hash, "$temp_path" . "tha_rules/so_rules/",
			$local_rules );
	}
}
else { Help("Check your oinkcode, temp path and freespace!"); }

if ( !$grabonly ) {
	if ( $sid_changelog && -f $Output ) {
	    read_rules( \%oldrules_hash, "$Output", $local_rules );
	}
	if ( $sid_changelog && $Sostubs && -f $Sostubs ) {
	    read_rules( \%oldrules_hash, "$Sostubs", $local_rules );
	}
}

if ( -d $temp_path ) {
    temp_cleanup();
}

if (!$grabonly ) {
	if ( $ips_policy ne "Disabled" ) {
	    policy_set( $ips_policy, \%rules_hash );
	}
	
	foreach (@sidact) {
		if ( $sidmod{$_} && -f $sidmod{$_} ) {
			modify_state( $_, $sidmod{$_}, \%rules_hash );
		}
	}
	
	if ( $sidmod{modify} && -f $sidmod{modify} ) {
	    modify_sid( \%rules_hash, $sidmod{modify} );
	}
	
	print "Setting Flowbit State....\n";
	my $fbits = 1;
	while ( $fbits > 0 ) {
	    $fbits = flowbit_set( \%rules_hash );
	}
	print "\tDone\n";
	
	if ($Output) {
	    rule_write( \%rules_hash, $Output, 1 );
	}
	if ( $Sostubs && !$Textonly ) {
	    rule_write( \%rules_hash, $Sostubs, 3 );
	}
	
	if ($sid_msg_map) {
	
	    sid_msg( \%rules_hash, \%sid_msg_map );
	    sid_write( \%sid_msg_map, $sid_msg_map );
	}
	
	if ( $SigHup && $pid_path ne "" ) {
	    sig_hup($pid_path) unless $Sostubs;
	    print "WARNING, cannot send sighup if also processing SO rules",
	      "\n\tsee README.SHAREDOBJECTS\n", "\tor use -T flag!\n"
	      if $Sostubs;
	}
	
	if ( $sid_changelog && -f $Output ) {
	    changelog( $sid_changelog, \%rules_hash, \%oldrules_hash, $ips_policy );
	}
}
print("Fly Piggy Fly!\n");
syslogit( 'warning|local0', "INFO: Finished Cleanly" ) if $Syslogging;
__END__
