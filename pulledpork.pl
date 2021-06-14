#!/usr/bin/env perl

## pulledpork v(whatever it says below!)

# Copyright (C) 2009-2021 JJ Cummings, Michael Shirk and the PulledPork Team!

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

#use Crypt::SSLeay;
use Sys::Syslog;
use Digest::MD5;
use File::Path;
use File::Find;
use File::Basename;
use Getopt::Long qw(:config no_ignore_case bundling);
use Archive::Tar;
use POSIX qw(:errno_h);
use Cwd;
use Carp;
use Data::Dumper;

### Vars here

# we are gonna need these!
my ($oinkcode, $temp_path, $rule_file, $Syslogging);
my $VERSION = "0.8.0";
my $HUMOR   = "The only positive thing to come out of 2020...well this and take-out liquor!";
my $ua      = LWP::UserAgent->new;

#Read in proxy settings from the environment
$ua->env_proxy;

#Add PulledPork version to the user agent
$ua->agent("PulledPork v$VERSION");

# for certificate validation, check for the operating system
# and set the path to the certificate store if required.
my $oSystem = "$^O";
my $CAFile  = "OS Default";
if ($oSystem =~ /freebsd/i) {

    #Check to ensure the cert file exists
    if (-e "/etc/ssl/cert.pem") {
        $CAFile = "/etc/ssl/cert.pem";
        if (-r $CAFile) {
            $ua->ssl_opts(SSL_ca_file => $CAFile);
        }
        else {
            carp "ERROR: $CAFile is not readable by "
                . (getpwuid($<))[0] . "\n";
            syslogit('err|local0',
                "FATAL: ERROR: $CAFile is not readable by "
                    . (getpwuid($<))[0] . "\n")
                if $Syslogging;
            exit(1);
        }

        #Check for the other location for the cert file
    }
    elsif (-e "/usr/local/etc/ssl/cert.pem") {
        $CAFile = "/usr/local/etc/ssl/cert.pem";
        if (-r $CAFile) {
            $ua->ssl_opts(SSL_ca_file => $CAFile);
        }
        else {
            carp "ERROR: $CAFile is not readable by "
                . (getpwuid($<))[0] . "\n";
            syslogit('err|local0',
                "FATAL: ERROR: $CAFile is not readable by "
                    . (getpwuid($<))[0] . "\n")
                if $Syslogging;
            exit(1);
        }
    }
    else {
        carp
            "ERROR: cert file does not exist (/etc/ssl/cert.pem or /usr/local/etc/ssl/cert.pem) Ensure that the ca_root_nss port/pkg is installed, or use -w to skip SSL verification\n";
        syslogit('err|local0',
            "FATAL: cert file does not exist. Ensure that the ca_root_nss port/pkg is installed, or use -w to skip SSL verification\n"
        ) if $Syslogging;
        exit(1);
    }
}

my ($Hash,         $ALogger,    $Config_file, $Sorules,       $Auto);
my ($Output,       $Distro,     $Snort,       $sid_changelog, $ignore_files);
my ($Snort_config, $Snort_path, $Textonly,    $grabonly,      $ips_policy,);
my ($pid_path,     $SigName,    $NoDownload,  $sid_msg_map,   @base_url);
my ($local_rules,  $arch,       @records,     $enonly);
my ($rstate, $keep_rulefiles, $rule_file_path, $prefix, $block_list);
my ($Process, $hmatch, $bmatch, $sid_msg_version, $skip_verify,
    $proxy_workaround);
my $Sostubs = 1;
my $Snortv3 = 0;

# verbose and quiet control print()
# default values if not set otherwise in getopt
# $Verbose = 0 is normal output (default behaviour)
# $Verbose = 1 is loud output
# $Verbose = 2 is troubleshooting output
# $Quiet   = 0 leaves verbosity as default or otherwise set
# $Quiet   = 1 suppresses all but FAIL messages, eg, anything preceding an exit

my $Verbose = 0;
my $Quiet   = 0;

undef($Hash);
undef($ALogger);

my %rules_hash    = ();
my %blocklist     = ();
my %oldrules_hash = ();
my %sid_msg_map   = ();
my %sidmod        = ();
my $categories    = ();
undef %rules_hash;
undef %oldrules_hash;
undef %sid_msg_map;

## initialize some vars
my $rule_digest = "";
my $md5         = "";

# Vars the subroutine to fetch config values
my ($Config_key);
my %Config_info = ();

### Subroutines here

## routine to grab our config from the defined config file
sub parse_config_file {
    my ($FileConf, $Config_val) = @_;
    my ($config_line, $Name, $Value);

    if (!open(CONFIG, "$FileConf")) {
        carp "ERROR: Config file not found : $FileConf\n";
        syslogit('err|local0', "FATAL: Config file not found: $FileConf")
            if $Syslogging;
        exit(1);
    }
    open(CONFIG, "$FileConf");
    while (<CONFIG>) {
        $config_line = $_;
        chomp($config_line);
        $config_line = trim($config_line);
        if (($config_line !~ /^#/) && ($config_line ne "")) {
            ($Name, $Value) = split(/=/, $config_line);
            if ($Value =~ /,/ && $Name eq "rule_url") {
                push(@{ $$Config_val{$Name} }, split(/,/, $Value));
            }
            elsif ($Name eq "rule_url") {
                push(@{ $$Config_val{$Name} }, split(/,/, $Value))
                    if $Value;
            }
            else {
                $$Config_val{$Name} = $Value;
            }
        }
    }

    close(CONFIG);

}

## Help routine.. display help to stdout then exit
sub Help {
    my $msg = shift;
    if ($msg) { print "\nERROR: $msg\n"; }

    print <<__EOT;
  Usage: $0 [-dEgklnRTPVvv? -help] -c <config filename> -o <rule output path>
   -O <oinkcode> -s <so_rule output directory> -D <Distro> -S <SnortVer>
   -p <path to your snort binary> -C <path to your snort.conf> -t <sostub output path>
   -h <changelog path> -H <signal_name> -I (security|connectivity|balanced) -i <path to disablesid.conf>
   -b <path to dropsid.conf> -e <path to enablesid.conf> -M <path to modifysid.conf>

   Options:
   -help/? Print this help info.
   -b Where the dropsid config file lives.
   -C Path to your snort.conf
   -c Where the pulledpork config file lives.
   -d Do not verify signature of rules tarball, i.e. downloading fron non VRT or ET locations.
   -D What Distro are you running on, for the so_rules
      For latest supported options see http://www.snort.org/snort-rules/shared-object-rules
      Valid Distro Types:
	Alpine-3-10
	Centos-6, Centos-7, Centos-8
	Debian-8, Debian-9, Debian-10
	FC-27, FC-30
	FreeBSD-11, FreeBSD-12
	OpenBSD-6-2, OpenBSD-6-4, OpenBSD-6-5 
	OpenSUSE-15-0, OpenSUS-15-1, OpenSUSE-42-3
	RHEL-6, RHEL-7, RHEL-8
	Slackware-14-2
	Ubuntu-14-4, Ubuntu-16-4, Ubuntu-17-10, Ubuntu-18-4
   -e Where the enablesid config file lives.
   -E Write ONLY the enabled rules to the output files.
   -g grabonly (download tarball rule file(s) and do NOT process)
   -h path to the sid_changelog if you want to keep one?
   -H Send signal_name to the pids listed in the config file (SIGHUP or SIGUSR2)
   -I Specify a base ruleset( -I security,connectivity,or balanced, see README.RULESET)
   -i Where the disablesid config file lives.
   -k Keep the rules in separate files (using same file names as found when reading)
   -K Where (what directory) do you want me to put the separate rules files?
   -l Log Important Info to Syslog (Errors, Successful run etc, all items logged as WARN or higher)
   -L Where do you want me to read your local.rules for inclusion in sid-msg.map
   -m where do you want me to put the sid-msg.map file?
   -M where the modifysid config file lives.
   -n Do everything other than download of new files (disablesid, etc)
   -o Where do you want me to put generic rules file?
   -O Define the oinkcode on the command line (necessary for some users)
   -p Path to your Snort binary
   -P Process rules even if no new rules were downloaded
   -R When processing enablesid, return the rules to their ORIGINAL state
   -S What version of snort are you using (2.8.6 or 2.9.0) are valid values
   -s Where do you want me to put the so_rules?
   -T Process text based rules files only, i.e. DO NOT process so_rules
   -u Where do you want me to pull the rules tarball from
      ** E.g., ET, Snort.org. See pulledpork config rule_url option for value ideas
   -V Print Version and exit
   -v Verbose mode, you know.. for troubleshooting and such nonsense.
   -vv EXTRA Verbose mode, you know.. for in-depth troubleshooting and other such nonsense.
   -w Skip the SSL verification (if there are issues pulling down rule files)
   -W Where you want to work around the issue where some implementations of LWP do not work with pulledpork's proxy configuration.
__EOT

    exit(0);
}

## OMG We MUST HAVE FLYING PIGS!
sub pulledpork {

    print <<__EOT;

    https://github.com/shirkdog/pulledpork
      _____ ____
     `----,\\    )
      `--==\\\\  /    PulledPork v$VERSION - $HUMOR
       `--==\\\\/
     .-~~~~-.Y|\\\\_  Copyright (C) 2009-2021 JJ Cummings, Michael Shirk
  \@_/        /  66\\_  and the PulledPork Team!
    |    \\   \\   _(\")
     \\   /-| ||'--'  Rules give me wings!
      \\_\\  \\_\\\\
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

__EOT
}

## subroutine to cleanup the temp rubbish!!!
sub temp_cleanup {
    my $remove = rmtree($temp_path . "tha_rules");
    if ($Verbose && !$Quiet) {
        print "Cleanup....\n";
        print
            "\tremoved $remove temporary snort files or directories from $temp_path"
            . "tha_rules!\n";
    }
}

# subroutine to extract the files to a temp path so that we can do what we need to do..
sub rule_extract {
    my ($rule_file, $temp_path, $Distro, $arch, $Snort,
        $Sorules, $ignore, $prefix, $Snortv3)
        = @_;

    #special case to bypass file operations when -nPT are specified
    my $BypassTar = 0;
    if (!$BypassTar) {
        print "Prepping rules from $rule_file for work....\n" if !$Quiet;
        print "\textracting contents of $temp_path$rule_file...\n"
            if ($Verbose && !$Quiet);
    }
    mkpath($temp_path . "tha_rules");
    mkpath($temp_path . "tha_rules/so_rules");
    my $tar = Archive::Tar->new();
    if (!$BypassTar) {
        $tar->read($temp_path . $rule_file);
        $tar->setcwd(cwd());
    }
    local $Archive::Tar::CHOWN = 0;
    my @ignores = split(/,/, $ignore) if (defined $ignore);

    foreach (@ignores) {
        if ($_ =~ /\.rules/) {
            print "\tIgnoring plaintext rules: $_\n" if ($Verbose && !$Quiet);
            $tar->remove("rules/$_");
        }
        elsif ($_ =~ /\.preproc/) {
            print "\tIgnoring preprocessor rules: $_\n"
                if ($Verbose && !$Quiet);
            my $preprocfile = $_;
            $preprocfile =~ s/\.preproc/\.rules/;
            $tar->remove("preproc_rules/$preprocfile");
        }
        elsif ($_ =~ /\.so/) {
            print "\tIgnoring shared object rules: $_\n"
                if ($Verbose && !$Quiet);
            $tar->remove("so_rules/precompiled/$Distro/$arch/$Snort/$_");
        }
        else {
            print "\tIgnoring all rule types in $_ category!\n"
                if ($Verbose && !$Quiet);
            $tar->remove("rules/$_.rules");
            $tar->remove("preproc_rules/$_.rules");
            $tar->remove("so_rules/precompiled/$Distro/$arch/$Snort/$_");
        }
    }
    my $sofile_pat_base = "^so_rules\/precompiled\/";
    if ($Snortv3 == 0) {
        $sofile_pat_base = $sofile_pat_base . "($Distro)\/($arch)\/($Snort)\/";
    }
    else {
	$sofile_pat_base = $sofile_pat_base . "($Distro)-($arch)\/";
    }
    my $sofile_pat = $sofile_pat_base . ".*\.so";
    my @files = $tar->get_files();
    foreach (@files) {
        my $filename   = $_->name;
        my $singlefile = $filename;
        if ($filename =~ /^(community-)?rules\/.*\.rules$/) {
            $singlefile =~ s/^(community-)?rules\///;
            $tar->extract_file($filename,
                $temp_path . "/tha_rules/$prefix" . $singlefile);
            print "\tExtracted: /tha_rules/$prefix$singlefile\n"
                if ($Verbose && !$Quiet);
        }
        elsif ($filename =~ /^preproc_rules\/.*\.rules$/) {
            $singlefile =~ s/^preproc_rules\///;
            $tar->extract_file($filename,
                $temp_path . "/tha_rules/$prefix" . $singlefile);
            print "\tExtracted: /tha_rules/$prefix$singlefile\n"
                if ($Verbose && !$Quiet);
        }
        elsif ($Sorules
            && $filename
            =~ m/$sofile_pat/
            && -d $Sorules
            && !$Textonly)
        {
            $singlefile
                =~ s/$sofile_pat_base//;
            $tar->extract_file($filename, $Sorules . $singlefile);
            print "\tExtracted: $Sorules$singlefile\n"
                if ($Verbose && !$Quiet);
        }
    }
    print "\tDone!\n" if (!$Verbose && !$Quiet);
}

## subroutine to actually check the md5 values, if they match we move onto file manipulation routines
sub compare_md5 {
    my (
        $oinkcode, $rule_file, $temp_path,   $Hash,
        $base_url, $md5,       $rule_digest, $Distro,
        $arch,     $Snort,     $Sorules,     $ignore_files,
        $prefix,   $Process,   $hmatch,      $fref
    ) = @_;
    if ($rule_digest =~ $md5 && !$Hash) {
        if ($Verbose && !$Quiet) {
            print "\tThe MD5 for $rule_file matched $md5\n\n";
        }
        if (!$Verbose && !$Quiet) { print "\tThey Match\n\tDone!\n"; }
        return (1);
    }
    elsif ($rule_digest !~ $md5 && !$Hash) {
        if ($Verbose && !$Quiet) {
            print
                "\tThe MD5 for $rule_file did not match the latest digest... so I am gonna fetch the latest rules file!\n";
        }
        if (!$Verbose && !$Quiet) { print "\tNo Match\n\tDone\n"; }
        rulefetch($oinkcode, $rule_file, $temp_path, $base_url);
        $rule_digest = md5sum($rule_file, $temp_path);
        $fref->{EXTRACT} = 1 if !$grabonly;
        return (
            compare_md5(
                $oinkcode, $rule_file, $temp_path,   $Hash,
                $base_url, $md5,       $rule_digest, $Distro,
                $arch,     $Snort,     $Sorules,     $ignore_files,
                $prefix,   $Process,   $hmatch,      $fref
            )
        );
    }
    elsif ($Hash) {
        if ($Verbose && !$Quiet) {
            print
                "\tOk, not verifying the digest.. lame, but that's what you specified!\n";
            print
                "\tSo if the rules tarball doesn't extract properly and this script croaks.. it's your fault!\n";
            print "\tNo Verify Set\n\tDone!\n";
        }
        $fref->{EXTRACT} = 1 if !$grabonly;
        return (1);
    }
    else {
        return ($hmatch);
    }
}

sub _get_ua_request {
    my ($ua, $method, $url, $file) = @_;
    my $request  = HTTP::Request->new($method => $url);
    my $response = $ua->request($request, $file);
    if ($response->is_success) {
        return $response->code;
    }

    # TODO: 4XX catching
    my $msg = sprintf("Error downloading %s: %s [ %d ]",
        $url, $response->status_line, $response->code);
    syslogit('err|local0', $msg) if $Syslogging;
    die $msg, $/;
}

## mimic LWP::Simple getstore routine - Thx pkthound!
sub getstore {
    my ($url, $file) = @_;
    my $method = "GET";

    #Workaround proxy issues, depends on version of LWP
    #May need to be addressed in the future
    if ($ua->proxy("https") && $url =~ /^https:/ && !$proxy_workaround) {
        $method = "CONNECT";
    }
    else {
        $method = "GET";
    }

    # on the first run, the file may not exist, so check.
    if (-e $file) {

        # Check to ensure the user has write access to the file
        if (-r $file && -w _) {
            return _get_ua_request($ua, $method, $url, $file);
        }
        else {
            carp "ERROR: $file is not writable by "
                . (getpwuid($<))[0] . "\n";
            syslogit('err|local0',
                "FATAL: $file is not writable by " . (getpwuid($<))[0] . "\n")
                if $Syslogging;
            exit(1);
        }
    }
    else {
        return _get_ua_request($ua, $method, $url, $file);
    }
}

## time to grab the real 0xb33f
sub rulefetch {
    my ($oinkcode, $rule_file, $temp_path, $base_url) = @_;
    print "Rules tarball download of $rule_file....\n"
        if (!$Quiet
        && $rule_file !~ /IPBLOCKLIST/
        && $oinkcode  !~ /RULEFILE/);
    print "Rule file download of $rule_file....\n"
        if (!$Quiet
        && $rule_file !~ /IPBLOCKLIST/
        && $oinkcode  =~ /RULEFILE/);
    print "IP Blocklist download of $base_url....\n"
        if (!$Quiet
        && $rule_file =~ /IPBLOCKLIST/
        && $oinkcode  !~ /RULEFILE/);
    $base_url = slash(0, $base_url);
    my ($getrules_rule);
    if ($Verbose && !$Quiet) {
        print "\tFetching rules file: $rule_file\n"
            if ($rule_file !~ /IPBLOCKLIST/ && $oinkcode !~ /RULEFILE/);
        if ($Hash && $rule_file !~ /IPBLOCKLIST/ && $oinkcode !~ /RULEFILE/) {
            print "But not verifying MD5\n";
        }
    }
    if ($base_url =~ /[^labs]\.snort\.org/i) {
        $getrules_rule
            = getstore(
            "https://www.snort.org/rules/$rule_file\?oinkcode=$oinkcode",
            $temp_path . $rule_file);
    }
    elsif ($rule_file =~ /IPBLOCKLIST/ && !$NoDownload) {
        my $rand = rand(1000);
        $getrules_rule
            = getstore($base_url, $temp_path . "$rand-block_list.rules");
        read_iplist(\%blocklist, $temp_path . "$rand-block_list.rules");
        unlink($temp_path . "$rand-block_list.rules");
    }
    elsif ($oinkcode =~ /RULEFILE/ && !$NoDownload) {
        my $rand = rand(1000);
        mkpath($temp_path . "/tha_rules");
        $getrules_rule = getstore($base_url . "/" . $rule_file,
            $temp_path . "/tha_rules/" . $rule_file);
    }
    else {
        $getrules_rule
            = getstore($base_url . "/" . $rule_file, $temp_path . $rule_file);
    }
    if ($getrules_rule == 403) {
        print
            "\tA 403 error occurred, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n",
            "\tYou may also wish to verify your oinkcode, tarball name, and other configuration options\n";
        syslogit('emerg|local0', "FATAL: 403 error occured") if $Syslogging;
        exit(1);    # For you shirkdog
    }
    elsif ($getrules_rule == 404) {
        print
            "\tA 404 error occurred, please verify your filenames and urls for your tarball!\n";
        syslogit('emerg|local0', "FATAL: 404 error occured") if $Syslogging;
        exit(1);    # For you shirkdog
    }
    elsif ($getrules_rule == 500) {
        print
            "\tA 500 error occurred, please verify that you have recently updated your root certificates!\n";
        syslogit('emerg|local0', "FATAL: 500 error occured") if $Syslogging;
        exit(1);    # Certs bitches!
    }
    unless (is_success($getrules_rule)) {
        syslogit('emerg|local0',
            "FATAL: Error $getrules_rule when fetching $rule_file")
            if $Syslogging;
        croak "\tError $getrules_rule when fetching " . $rule_file;
    }

    if ($Verbose && !$Quiet && $rule_file !~ /IPBLOCKLIST/) {
        print("\tstoring file at: $temp_path$rule_file\n\n");
    }
    if (!$Verbose && !$Quiet) { "\tDone!\n"; }
}

## subroutine to deterine the md5 digest of the current rules file
sub md5sum {
    my ($rule_file, $temp_path) = @_;
    open(MD5FILE, "$temp_path$rule_file")
        or croak $!;
    binmode(MD5FILE);
    $rule_digest = Digest::MD5->new->addfile(*MD5FILE)->hexdigest;
    close(MD5FILE);
    if ($@) {
        print $@;
        return "";
    }
    if ($Verbose && !$Quiet) {
        print "\tcurrent local rules file  digest: $rule_digest\n";
    }
    return $rule_digest;
}

## subroutine to fetch the latest md5 digest signature file from snort.org
sub md5file {
    my ($oinkcode, $rule_file, $temp_path, $base_url) = @_;
    my ($getrules_md5, $md5) = "";
    $base_url = slash(0, $base_url);
    print "Checking latest MD5 for $rule_file....\n" if !$Quiet;
    print "\tFetching md5sum for: " . $rule_file . ".md5\n"
        if ($Verbose && !$Quiet);
    if ($base_url =~ /[^labs]\.snort\.org/i) {
        $getrules_md5 = getstore(
            "https://www.snort.org/rules/$rule_file.md5\?oinkcode=$oinkcode",
            $temp_path . $rule_file . ".md5"
        );
    }
    elsif ($base_url
        =~ /(secureworks|emergingthreats\.net|emergingthreatspro\.com|snort\.org.+community)/i
        )
    {
        $getrules_md5 = getstore(
            "$base_url/$rule_file" . ".md5",
            $temp_path . $rule_file . ".md5"
        );
    }
    if ($getrules_md5 == 403) {
        print
            "\tA 403 error occurred, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n",
            "\tYou may also wish to verify your oinkcode, tarball name, and other configuration options\n";
    }
    elsif ($getrules_md5 == 429) {
        print
            "\tA 429 error occurred, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n",
            "\tYou may also wish to verify your oinkcode, tarball name, and other configuration options\n";
    }
    elsif ($getrules_md5 == 404) {
        print
            "\tA 404 error occurred, please verify your filenames and urls for your tarball!\n";
    }

    open(FILE, "$temp_path$rule_file.md5")
        or warn $!;
    $md5 = <FILE>;
    chomp($md5);
    close(FILE);
    $md5 =~ /\w{32}/
        ; ## Lets just grab the hash out of the string.. don't care about the rest!
    $md5 = $&;

    if ($Verbose && !$Quiet) {
        print "\tmost recent rules file digest: $md5\n";
    }
    return $md5;
}

## This sub allows for ip-reputation list de-duplication and processing:
sub read_iplist {
    my ($href, $path) = @_;
    print "\t"                   if ($Verbose && !$Quiet);
    print "Reading IP List...\n" if !$Quiet;
    open(FH, '<', $path) || croak "Couldn't read $path - $!\n";
    while (<FH>) {
        chomp();

        # we only want valid IP addresses, otherwise shiz melts!
        next
            unless $_
            =~ /(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
        $_ = trim($_);
        $_ =~ s/,*//;
        $href->{$_} = 1;
    }
    close(FH);
}

## This replaces the copy_rules routine and allows for in-memory processing
# of disablesid, enablesid, dropsid and other sid functions.. here we place
# all of the rules values into a hash as {$gid}{$sid}=$rule
sub read_rules {
    my ($hashref, $path, $extra_rules) = @_;
    my ($file, $sid, $gid, @elements);
    print "\t"                 if ($Verbose && !$Quiet);
    print "Reading rules...\n" if !$Quiet;
    my $reading_old_rules = $path eq ($rule_file_path || '');
    my @local_rules       = split(/,/, $extra_rules);
    foreach (@local_rules)
    {    #First let's read our local rules and assign a gid of 0
        $extra_rules = slash(0, $_);
        $file        = basename($extra_rules);
        if ($extra_rules && -f $extra_rules) {
            open(DATA, "$extra_rules")
                || croak "Couldn't read $extra_rules - $!\n";
            my @extra_raw = <DATA>;
            close(DATA);
            my $trk = 0;
            my $record;
            foreach my $row (@extra_raw) {
                $row = trim($row);
                chomp($row);
                if ($row =~ /^\s*#*\s*(alert|drop|pass)/i || $trk == 1) {
                    if (($row !~ /^#/) && ($row ne "")) {
                        if ($row =~ /\\$/) {    # handle multiline rules here
                            $row =~ s/\\$//;
                            $record .= $row;
                            $trk = 1;
                        }
                        elsif ($row !~ /\\$/ && $trk == 1)
                        {    # last line of multiline rule here
                            $record .= $row;
                            if ($record =~ /\ssid:\s*\d+\s*;/i) {
                                $sid = $&;
                                $sid =~ s/\ssid:\s*//;
                                $sid =~ s/\s*;//;
                                $$hashref{0}{ trim($sid) }{'rule'} = $record;
                            }
                            $trk = 0;
                            undef $record;
                        }
                        else {
                            if ($row =~ /\ssid:\s*\d+\s*;/i) {
                                $sid = $&;
                                $sid =~ s/\ssid:\s*//;
                                $sid =~ s/\s*;//;
                                $$hashref{0}{ trim($sid) }{'rule'} = $row;
                            }
                            $trk = 0;
                        }
                        if ($trk == 0) {
                            $sid = trim($sid);
                            my $rule = $$hashref{0}{$sid}{'rule'};
                            if ($rule =~ /^\s*\#+/) {
                                $$hashref{0}{$sid}{'state'} = 0;
                            }
                            elsif ($rule =~ /^\s*(alert|pass|drop)/) {
                                $$hashref{0}{$sid}{'state'} = 1;
                            }
                            $file =~ s/\.rules//;
                            $$hashref{0}{$sid}{'category'} = $file;

                            $categories->{$file}{0}{$sid} = 1;
                        }
                    }
                }
            }
            undef @extra_raw;
        }
    }
    if (-d $path) {
        opendir(DIR, "$path");
        while (defined($file = readdir DIR)) {
            my $fullpath = $path.$file;
            if (grep /^$fullpath$/, @local_rules) {
                next;
            }
            else {
                open(DATA, "$fullpath");
                @elements = <DATA>;
                close(DATA);
            }
            foreach my $rule (@elements) {
                chomp($rule);
                $rule = trim($rule);
                if ($rule =~ /^\s*#*\s*(alert|drop|pass)/i) {

                    if ($rule =~ /\ssid:\s*\d+\s*;/i) {
                        $sid = $&;
                        $sid =~ s/\ssid:\s*//;
                        $sid =~ s/\s*;//;
                        if ($rule =~ /\sgid:\s*\d+/i) {
                            $gid = $&;
                            $gid =~ s/\sgid:\s*//;
                        }
                        else { $gid = 1; }
                        if ($rule =~ /flowbits:\s*((un)?set(x)?|toggle)/i) {

                            # There is a much cleaner way to do this, I just don't have the time to do it right now!
                            my ($header, $options)
                                = split(/^[^"]* \(/, $rule);
                            my @optarray = split(/(?<!\\);(\t|\s)*/, $options)
                                if $options;
                            foreach my $option (reverse(@optarray)) {
                                my ($kw, $arg) = split(/:/, $option)
                                    if $option;
                                next
                                    unless ($kw && $arg && $kw eq "flowbits");
                                my ($flowact, $flowbit) = split(/,/, $arg);
                                next
                                    unless $flowact
                                    =~ /^\s*((un)?set(x)?|toggle)/i;
                                $$hashref{ trim($gid) }{ trim($sid) }
                                    { trim($flowbit) } = 1;
                            }

                        }
                        if ($rule =~ /^\s*\#+/) {
                            $$hashref{ trim($gid) }{ trim($sid) }{'state'}
                                = 0;
                        }
                        elsif ($rule =~ /^\s*(alert|pass|drop)/) {
                            $$hashref{ trim($gid) }{ trim($sid) }{'state'}
                                = 1;
                        }
                        $file =~ s/\.rules//;
                        $file = "VRT-SO-$file"
                            if ($gid == 3 && $file !~ /VRT-SO/);
                        $$hashref{ trim($gid) }{ trim($sid) }{'rule'} = $rule;
                        $$hashref{ trim($gid) }{ trim($sid) }{'category'}
                            = $file;

                        next if $reading_old_rules;

                        $categories->{$file}{ trim($gid) }{ trim($sid) } = 1;
                    }
                }
            }
        }
        close(DIR);
    }
    elsif (-f $path) {
        open(DATA, "$path") || croak "Couldn't read $path - $!";
        @elements = <DATA>;
        close(DATA);

        foreach my $rule (@elements) {
            if ($rule =~ /^\s*#*\s*(alert|drop|pass)/i) {
                if ($rule =~ /\ssid:\s*\d+/) {
                    $sid = $&;
                    $sid =~ s/\ssid:\s*//;
                    if ($rule =~ /\sgid:\s*\d+/i) {
                        $gid = $&;
                        $gid =~ s/\sgid:\s*//;
                    }
                    else { $gid = 1; }
                    if ($rule =~ /flowbits:\s*((un)?set(x)?|toggle)/) {
                        my ($header, $options) = split(/^[^"]* \(/, $rule);

                        # There is a much cleaner way to do this, I just don't have the time to do it right now!
                        my @optarray = split(/(?<!\\);(\t|\s)*/, $options)
                            if $options;
                        foreach my $option (reverse(@optarray)) {
                            my ($kw, $arg) = split(/:/, $option) if $option;
                            next unless ($kw && $arg && $kw eq "flowbits");
                            my ($flowact, $flowbit) = split(/,/, $arg);
                            next
                                unless $flowact
                                =~ /^\s*((un)?set(x)?|toggle)/i;
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

## sub to generate stub files using the snort --dump-dynamic-rules option
sub gen_stubs {
    my ($Snort_path, $Snort_config, $Sostubs, $Snortv3, $Sorules) = @_;
    print "Generating Stub Rules....\n" if !$Quiet;
    unless (-B $Snort_path) {
        Help("$Snort_path is not a valid binary file");
    }
    if (-d $Sostubs && -B $Snort_path && -f $Snort_config) {
        my $cmd = "";
        if ($Snortv3) {
	    $cmd = "$Snort_path -c $Snort_config --plugin-path $Sorules --dump-dynamic-rules > $Sostubs/allso.rules";
	}
	else {
	    $cmd = "$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs"
	}
        if ($Verbose && !$Quiet) {
            print(
                "\tGenerating shared object stubs via: $cmd\n"
            );
        }
        if (!$Snortv3) {
            open(FH, "$cmd 2>&1|");
        } else {
			open(FH, "|-", "$cmd");
		}
        while (<FH>) {
            print "\t$_" if $_ =~ /Dumping/i && ($Verbose && !$Quiet);
            next unless $_ =~ /(err|warn|fail)/i;
            syslogit('warning|local0', "FATAL: An error occured: $_")
                if $Syslogging;
            print "\tAn error occurred: $_\n";

            # Yes, this is lame error reporting to stdout ...
        }
        close(FH);
    }
    else {
        print(
            "Something failed in the gen_stubs sub, please verify your shared object config!\n"
        );
        if ($Verbose && !$Quiet) {
            unless (-d $Sostubs) {
                Help(
                    "The path that you specified: $Sostubs does not exist! Please verify your configuration.\n"
                );
            }
            unless (-f $Snort_path) {
                Help(
                    "The file that you specified: $Snort_path does not exist! Please verify your configuration.\n"
                );
            }
            unless (-f $Snort_config) {
                Help(
                    "The file that you specified: $Snort_config does not exist! Please verify your configuration.\n"
                );
            }
        }
    }
    print "\tDone\n" if !$Quiet;
}

sub vrt_policy {
    my ($ids_policy, $rule) = @_;
    my ($gid, $sid);
    if ($rule =~ /policy\s$ids_policy/i && $rule !~ /flowbits\s*:\s*noalert/i)
    {
        $rule =~ s/^#*\s*//;
    }
    elsif ($rule !~ /^\s*#/) {
        $rule = "# $rule";
    }
    return $rule;
}

sub policy_set {
    my ($ids_policy, $hashref) = @_;
    if ($hashref) {
        if ($ids_policy ne "Disabled" && $ids_policy ne "") {
            print "Activating $ids_policy rulesets....\n" if !$Quiet;
            foreach my $k (sort keys %$hashref) {
                foreach my $k2 (keys %{ $$hashref{$k} }) {
                    $$hashref{$k}{$k2}{'rule'}
                        = vrt_policy($ids_policy, $$hashref{$k}{$k2}{'rule'});
                }
            }

            print "\tDone\n" if !$Quiet;
        }
    }
}

## this allows the user to use regular expressions to modify rule contents
sub modify_sid {
    my ($href, $file) = @_;
    my @arry;
    print "Modifying Sids....\n" if !$Quiet;
    open(FH, "<$file") || carp "Unable to open $file\n";
    while (<FH>) {
        next if (($_ =~ /^\s*#/) || ($_ eq " "));
        if ($_ =~ /([(\d+)?\d+|,|\*]*)\s+"(.+)"\s+"(.*)"/) {
            my ($ruleids, $from, $to) = ($1, $2, $3);
            @arry = split(/,/, $ruleids) if $ruleids !~ /\*/;
            @arry = "*"                  if $ruleids =~ /\*/;
            foreach my $ruleid (@arry) {
                $ruleid = trim($ruleid);
                my @rule_comp;
                @rule_comp = split(/-/, $ruleid, 2);
                my $sid = pop @rule_comp;
                my $gid = pop @rule_comp;
                if (not defined $gid) {
                    $gid = 1;
                }
                if ($sid ne "*" && safe_defined($href, $gid, $sid, 'rule')) {
                    print "\tModifying GID:$gid,SID:$sid from:$from to:$to\n"
                        if ($Verbose && !$Quiet);
                    $$href{$gid}{$sid}{'rule'} =~ s/$from/$to/;
                }
                elsif ($sid eq "*") {
                    print
                        "\tModifying ALL SIDS for GID:$gid from:$from to:$to\n"
                        if ($Verbose && !$Quiet);
                    foreach my $k (sort keys %{ $$href{$gid} }) {
                        $$href{$gid}{$k}{'rule'} =~ s/$from/$to/;
                    }
                }
            }
            undef @arry;
        }

        # Handle use case where we want to modify multiple sids based on
        # comment in rule (think multiple rules with same or similar comment)
        if ($_ =~ /^regex:'([^']+)'\s+"(.+)"\s+"(.*)"/) {
            my ($regex, $from, $to) = ($1, $2, $3);

            # Go through each rule in gid:1 and look for matching rules
            foreach my $sid (sort keys(%{ $$href{1} })) {
                next unless ($$href{1}{$sid}{'rule'} =~ /$regex/);
                print "\tModifying SID:$sid from:$from to:$to\n"
                    if ($Verbose && !$Quiet);
                $$href{1}{$sid}{'rule'} =~ s/$from/$to/;
            }
        }
    }

    print "\tDone!\n" if !$Quiet;
    close(FH);
}

## this relaces the enablesid, disablesid and dropsid functions..
# speed ftw!
sub modify_state {
    my ($function, $SID_conf, $hashref, $rstate) = @_;
    my (@sid_mod, $sidlist);
    print "Processing $SID_conf....\n" if !$Quiet;
    print "\tSetting rules specified in $SID_conf to their default state!\n"
        if (!$Quiet && $function eq 'enable' && $rstate);
    if (-f $SID_conf) {
        open(DATA, "$SID_conf") or carp "unable to open $SID_conf $!";
        while (<DATA>) {
            next unless ($_ !~ /^\s*#/ && $_ ne "");
            $sidlist = (split '#', $_)[0];
            chomp($sidlist);
            $sidlist = trim($sidlist);
            if (!@sid_mod) {
                @sid_mod = split(/,/, $sidlist);
            }
            elsif (@sid_mod) {
                push(@sid_mod, split(/,/, $sidlist));
            }
        }
        close(DATA);
        if ($hashref) {
            my $sidcount  = 0;
            my $skipcount = 0;
            foreach (@sid_mod) {

                # ranges
                if ($_ =~ /^(\d+):\d+-\1:\d+/) {
                    my ($lsid, $usid) = split(/-/, $&);
                    my $gid = $lsid;
                    $sid_mod[$sidcount] = $lsid;
                    $gid  =~ s/:\d+//;
                    $lsid =~ s/\d+://;
                    $usid =~ s/\d+://;
                    while ($lsid < $usid) {
                        $lsid++;
                        push(@sid_mod, $gid . ':' . $lsid);
                    }
                }

                # pcres
                elsif ($_ =~ /^pcre\:.+/i) {
                    my ($pcre, $regex) = split(/\:/, $&);
                    foreach my $k1 (keys %$hashref) {
                        foreach my $k2 (keys %{ $$hashref{$k1} }) {
                            next unless defined $$hashref{$k1}{$k2}{'rule'};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2
                                if (
                                ($$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i)
                                && ($sid_mod[$sidcount] =~ /[a-xA-X](\w|\W)*/)
                                );
                            push(@sid_mod, $k1 . ":" . $k2)
                                if (
                                ($$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i)
                                && ($sid_mod[$sidcount] =~ /\d+:\d+/));
                        }
                    }
                }

                # specific sid
                elsif ($_ =~ /^[a-xA-X]+\:.+/) {
                    my $regex = $&;
                    $regex =~ s/\:/,/;
                    foreach my $k1 (keys %$hashref) {
                        foreach my $k2 (keys %{ $$hashref{$k1} }) {
                            next unless defined $$hashref{$k1}{$k2}{'rule'};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2
                                if (
                                ($$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i)
                                && ($sid_mod[$sidcount] =~ /[a-xA-X](\w|\W)*/)
                                );
                            push(@sid_mod, $k1 . ":" . $k2)
                                if (
                                ($$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i)
                                && ($sid_mod[$sidcount] =~ /\d+:\d+/));
                        }
                    }
                }

                # MS reference
                elsif ($_ =~ /^MS\d+-.+/i) {
                    my $regex = $&;
                    foreach my $k1 (keys %$hashref) {
                        foreach my $k2 (keys %{ $$hashref{$k1} }) {
                            next unless defined $$hashref{$k1}{$k2}{'rule'};
                            $sid_mod[$sidcount] = $k1 . ":" . $k2
                                if (
                                ($$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i)
                                && ($sid_mod[$sidcount] =~ /[a-xA-X](\w|\W)*/)
                                );
                            push(@sid_mod, $k1 . ":" . $k2)
                                if (
                                ($$hashref{$k1}{$k2}{'rule'} =~ /($regex)/i)
                                && ($sid_mod[$sidcount] =~ /\d+:\d+/));
                        }
                    }
                }

                # Category
                elsif ($_ =~ /[a-xA-X]+(-|\w)*/) {
                    my $category = $&;
                    foreach my $k1 (keys %$hashref) {
                        foreach my $k2 (keys %{ $$hashref{$k1} }) {
                            next
                                unless
                                defined $$hashref{$k1}{$k2}{'category'};
                            next
                                unless $$hashref{$k1}{$k2}{'category'}
                                =~ /($category)/;
                            $sid_mod[$sidcount] = $k1 . ":" . $k2;
                            push(@sid_mod, $k1 . ":" . $k2)
                                if $sid_mod[$sidcount] =~ /\d+:\d+/;
                        }
                    }
                }
                $sidcount++;
            }
            $sidcount  = 0;
            $skipcount = 0;
            foreach (@sid_mod) {
                if ($_ =~ /^\d+:\d+/) {
                    my $gid = $&;
                    my $sid = $gid;
                    if ($gid && $sid) {
                        $gid =~ s/:\d+//;
                        $sid =~ s/\d+://;
                        if ($function) {
                            if ($function eq "enable") {
                                if (exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'}
                                    =~ /^\s*#\s*(alert|drop|pass)/i
                                    && !$rstate)
                                {
                                    $$hashref{$gid}{$sid}{'rule'}
                                        =~ s/^\s*#+\s*//;
                                    if ($Verbose && !$Quiet) {
                                        print "\tEnabled $gid:$sid\n";
                                    }
                                    $sidcount++;
                                }

                                # Return State!
                                next unless $$hashref{$gid}{$sid};
                                next unless $$hashref{$gid}{$sid}{rule};
                                if (   $$hashref{$gid}{$sid}{'state'}
                                    && $$hashref{$gid}{$sid}{'state'} == 0
                                    && $$hashref{$gid}{$sid}{'rule'}
                                    =~ /^\s*(alert|drop|pass)/
                                    && $rstate)
                                {
                                    $$hashref{$gid}{$sid}{'rule'} = "# "
                                        . $$hashref{$gid}{$sid}{'rule'};
                                    $sidcount++;
                                    if ($Verbose && !$Quiet) {
                                        print "\tRe-Disabled $gid:$sid\n";
                                    }
                                }
                                elsif ($$hashref{$gid}{$sid}{'state'}
                                    && $$hashref{$gid}{$sid}{'state'} == 1
                                    && $$hashref{$gid}{$sid}{'rule'}
                                    =~ /^\s*#+\s*(alert|drop|pass)/
                                    && $rstate)
                                {
                                    $$hashref{$gid}{$sid}{'rule'}
                                        =~ s/^\s*#+\s*//;
                                    $sidcount++;
                                    if ($Verbose && !$Quiet) {
                                        print "\tRe-Enabled $gid:$sid\n";
                                    }
                                }
                            }
                            elsif ($function eq "drop") {
                                if (exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'}
                                    =~ /^\s*#*\s*alert/i)
                                {
                                    $$hashref{$gid}{$sid}{'rule'}
                                        =~ s/^\s*#*\s*//;
                                    $$hashref{$gid}{$sid}{'rule'}
                                        =~ s/^alert/drop/;
                                    if ($Verbose && !$Quiet) {
                                        print "\tWill drop $gid:$sid\n";
                                    }
                                    $sidcount++;
                                }
                            }
                            elsif ($function eq "disable") {
                                if (exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'}
                                    =~ /^\s*(alert|drop|pass)/i)
                                {
                                    $$hashref{$gid}{$sid}{'rule'} = "# "
                                        . $$hashref{$gid}{$sid}{'rule'};
                                    $$hashref{$gid}{$sid}{'disabled'} = 1;
                                    if ($Verbose && !$Quiet) {
                                        print "\tDisabled $gid:$sid\n";
                                    }
                                    $sidcount++;
                                }
                                elsif (exists $$hashref{$gid}{$sid}
                                    && $$hashref{$gid}{$sid}{'rule'}
                                    =~ /^\s*#*\s*(alert|drop|pass)/i)
                                {
                                    $$hashref{$gid}{$sid}{'disabled'} = 1;
                                    if ($Verbose && !$Quiet) {
                                        print
                                            "\tAlready Disabled $gid:$sid\n";
                                    }
                                    $skipcount++;
                                }
                            }
                        }
                    }
                }
            }
            print "\tModified $sidcount rules\n" if !$Quiet;
            print "\tSkipped $skipcount rules (already disabled)\n"
                if !$Quiet;
        }
    }
    print "\tDone\n" if !$Quiet;
    undef @sid_mod;
}

## iprep control socket!
sub iprep_control {
    my ($bin, $path) = @_;
    return unless (defined $bin && -f $bin && -d $path);
    my $cmd = "$bin $path 1361";
    print "Issuing reputation socket reload command\n";
    print "Command: $cmd\n" if $Verbose;
    open(FH, "$cmd 2>&1 |");
    while (<FH>) {
        chomp();
        next unless $_ =~ /(warn|err|unable)/i;
        print "$_\n";
    }
    close(FH);
}

## goodbye
sub send_signal {
    my ($signal_name, $pidlist) = @_;
    my @pids = split(/,/, $pidlist);
    my $pid;
    print "Signaling Time....\n";
    foreach $pid (@pids) {
        open(FILE, "$pid")
            or croak $!;
        my $realpid = <FILE>;
        chomp($realpid);
        close(FILE);
        my $kill_ret = kill "$signal_name", $realpid;
        if ($Verbose && !$Quiet) {
            print
                "\tSent $signal_name signal to $realpid from $pid with result $kill_ret\n";
        }
    }
    if (!$Verbose && !$Quiet) { print "\tDone!\n"; }
    undef @pids;
}

## make the sid-msg.map
sub sid_msg {
    my ($ruleshash, $sidhash, $enonly) = @_;
    my ($gid, $arg, $msg);
    print "Generating sid-msg.map....\n" if !$Quiet;
    foreach my $k (sort keys %$ruleshash) {
        foreach my $k2 (sort keys %{ $$ruleshash{$k} }) {
            next
                if ((defined $enonly)
                && $$ruleshash{$k}{$k2}{'rule'} !~ /^\s*(alert|drop|pass)/);
            (my $header, my $options)
                = split(/^[^"]* \(\s*/, $$ruleshash{$k}{$k2}{'rule'})
                if defined $$ruleshash{$k}{$k2}{'rule'};
            my @optarray = split(/(?<!\\);\s*/, $options) if $options;
            foreach my $option (reverse(@optarray)) {
                my ($kw, $arg) = split(/:\s*/, $option, 2) if $option;
                my $gid = $k;
                $gid = 1 if $k == 0;
                next
                    unless ($kw
                    && $arg
                    && $kw =~ /(reference|msg|rev|classtype|priority)/);
                if ($kw eq "reference") {
                    push(@{ $$sidhash{$gid}{$k2}{refs} }, trim($arg));
                }
                elsif ($kw eq "msg") {
                    $arg =~ s/"//g;
                    $$sidhash{$gid}{$k2}{msg} = trim($arg);
                }
                elsif ($kw eq "rev") {
                    $$sidhash{$gid}{$k2}{rev} = trim($arg);
                }
                elsif ($kw eq "classtype") {
                    $$sidhash{$gid}{$k2}{classtype} = trim($arg);
                }
                elsif ($kw eq "priority") {
                    $$sidhash{$gid}{$k2}{priority} = trim($arg);
                }
            }
        }
    }
    print "\tDone\n" if !$Quiet;
}

## write the rules files to unique output files!
sub rule_category_write {
    my ($hashref, $filepath, $enonly, $extra_rules) = @_;
    print "Writing rules to unique destination files....\n" if !$Quiet;
    print "\tWriting rules to $filepath\n"                  if !$Quiet;

    my %hcategory = ();
    my $file;
    my @local_rules = split(/,/, $extra_rules);
    foreach my $fn (sort keys %$categories) {
        my $file = "$fn.rules";
        open(WRITE, '>', "$filepath$file");
        print WRITE "\n\n# ----- Begin $fn Rules Category ----- #\n";
        foreach my $gid (sort keys %{ $categories->{$fn} }) {
            print WRITE "\n# -- Begin GID:$gid Based Rules -- #\n\n";
            foreach my $sid (sort keys %{ $categories->{$fn}{$gid} }) {
                next unless defined $$hashref{$gid}{$sid}{'rule'};
                if (   $enonly
                    && $$hashref{$gid}{$sid}{'rule'}
                    =~ /^\s*(alert|drop|pass)/)
                {
                    print WRITE $$hashref{$gid}{$sid}{'rule'} . "\n";
                }
                elsif (!$enonly || grep /^$filepath$file$/, @local_rules) {
                    print WRITE $$hashref{$gid}{$sid}{'rule'} . "\n";
                }
            }
        }
        close(WRITE);
    }
    print "\tDone\n" if !$Quiet;
}

## write our blocklist and blocklist version file!
sub blocklist_write {
    my ($href, $path) = @_;
    my $blv   = $Config_info{'IPRVersion'} . "/IPRVersion.dat";
    my $blver = 0;

    # First lets be sure that our data is new, if not skip the rest of it!
    # We will MD5 our HREF then convert it to an integer.
    my $hobj = Digest::MD5->new;
    $hobj->add(%$href);
    my $hash = $hobj->hexdigest;
    my $ver  = unpack("i", $hash);

    if (-f $blv) {
        open(FH, '<', $blv);
        while (<FH>) {
            next unless $_ =~ /\d+/;
            $blver = $_;
        }
        close(FH);
    }

    if ($blver != $ver) {
        print "Writing Blocklist File $path....\n" if !$Quiet;
        open(FH, '>', $path)
            || croak("Unable to open $path for writing! - $!\n");
        foreach (sort keys %$href) {
            print FH "$_\n";
        }
        close(FH);

        print "Writing Blocklist Version $ver to $blv....\n" if !$Quiet;
        open(FH, '>', $blv)
            || croak("Unable to open $blv for writing! - $!\n");
        print FH $ver;
        close(FH);
        return (1);
    }
    else {
        print "Blocklist version is unchanged, not updating!\n" if !$Quiet;
        return (0);
    }

}

## write the rules to a single output file!
sub rule_write {
    my ($hashref, $file, $enonly) = @_;
    print "Writing $file....\n" if !$Quiet;
    open(WRITE, '>', "$file") || croak "Unable to write $file - $!\n";

    #if ( $gid == 1 ) {
    foreach my $fn (sort keys %$categories) {
        print WRITE "\n\n# ----- Begin $fn Rules Category ----- #\n";
        foreach my $gid (sort keys %{ $categories->{$fn} }) {
            print WRITE "\n# -- Begin GID:$gid Based Rules -- #\n\n";
            foreach my $sid (sort keys %{ $categories->{$fn}{$gid} }) {
                next unless defined $$hashref{$gid}{$sid}{'rule'};
                if (   $enonly
                    && $$hashref{$gid}{$sid}{'rule'}
                    =~ /^\s*(alert|drop|pass)/)
                {
                    print WRITE $$hashref{$gid}{$sid}{'rule'} . "\n";
                }
                elsif (!$enonly) {
                    print WRITE $$hashref{$gid}{$sid}{'rule'} . "\n";
                }
            }
        }
    }
    close(WRITE);
    print "\tDone\n" if !$Quiet;
}

## sid file time!
sub sid_write {
    my ($hashref, $file, $sid_msg_version) = @_;
    print "Writing v$sid_msg_version $file....\n" if !$Quiet;
    open(WRITE, ">$file") || croak "Unable to write $file -$!";
    print WRITE "#v$sid_msg_version\n";    # Version biznits!
    print WRITE
        "# sid-msg.map autogenerated by PulledPork - DO NOT MODIFY BY HAND!\n";
    foreach my $k (sort keys %$hashref) {
        foreach my $k2 (sort keys %{ $$hashref{$k} }) {
            if ($sid_msg_version == 2) {
                print WRITE "$k || $k2 || $hashref->{$k}{$k2}{rev} || ";
                if ($hashref->{$k}{$k2}{classtype}) {
                    print WRITE "$hashref->{$k}{$k2}{classtype} || ";
                }
                else { print WRITE "NOCLASS || "; }
                if ($hashref->{$k}{$k2}{priority}) {
                    print WRITE "$hashref->{$k}{$k2}{priority} || ";
                }
                else { print WRITE "0 || "; }
            }
            else {
                print WRITE "$k2 || ";
            }
            print WRITE "$hashref->{$k}{$k2}{msg}";
            foreach (@{ $hashref->{$k}{$k2}{refs} }) {
                print WRITE " || $_";
            }
            print WRITE "\n";
        }
    }
    close(WRITE);
    print "\tDone\n" if !$Quiet;
}

## Pull the flowbits requirements from the currently enabled rules.
# TODO: add extended functionality for setx, toggle and groups (Q1 of 2013)
sub flowbit_check {
    my ($rule,   $aref)    = @_;
    my ($header, $options) = split(/^[^"]* \(\s*/, $rule);
    my @optarray = split(/(?<!\\);\s*/, $options) if $options;
    foreach my $option (reverse(@optarray)) {
        my ($kw, $arg) = split(/:/, $option) if $option;
        next unless ($kw && $arg && $kw eq "flowbits");
        my ($flowact, $flowbit) = split(/,/, $arg);
        next unless $flowact =~ /is(not)?set/i;
        push(@$aref, trim($flowbit))                  if $flowbit !~ /(&|\|)/;
        push(@$aref, split(/(&|\|)/, trim($flowbit))) if $flowbit =~ /(&|\|)/;
    }
}

## Enable flowbits if there is a rule that requires them!
sub flowbit_set {
    my $href    = shift;
    my $counter = 0;
    my @flowbits;
    foreach my $k1 (keys %$href) {
        foreach my $k2 (keys %{ $$href{$k1} }) {
            next unless $$href{$k1}{$k2}{'rule'} =~ /^(alert|drop|pass)/;
            next
                unless $$href{$k1}{$k2}{'rule'}
                =~ /flowbits:\s*is(not)?set\s*,\s*[^;]+/i;
            flowbit_check($$href{$k1}{$k2}{'rule'}, \@flowbits);
        }
    }
    my %dups;
    map { $dups{$_} = 1 } @flowbits;
    @flowbits = keys %dups;
    undef %dups;
    foreach my $k1 (keys %$href) {
        foreach my $k2 (keys %{ $$href{$k1} }) {
            foreach my $flowbit (@flowbits) {
                next
                    unless defined $$href{$k1}{$k2}{$flowbit}
                    && $$href{$k1}{$k2}{'rule'}
                    =~ /^\s*#\s*(alert|drop|pass)/i;
                $$href{$k1}{$k2}{'rule'} =~ s/^\s*#\s*//;
                if (defined $$href{$k1}{$k2}{'disabled'}) {
                    print "\tWARN - $k1:$k2 is re-enabled by a",
                        " check of the $flowbit flowbit!\n"
                        if $Verbose && !$Quiet;
                }
                $counter++;
            }
        }
    }
    undef @flowbits;
    print "\tEnabled $counter flowbits\n" if ($counter > 0 && !$Quiet);
    return $counter;
}

## Make some changelog fun!
sub changelog {
    my ($changelog, $new_hash, $old_hash, $blocklist_hash, $ips_policy,
        $enonly, $hmatch)
        = @_;

    print "Writing $changelog....\n" if !$Quiet;
    my (@newsids, @delsids);
    undef @newsids;
    undef @delsids;
    my $rt       = 0;
    my $dt       = 0;
    my $dropped  = 0;
    my $enabled  = 0;
    my $disabled = 0;
    my $ips      = 0;

    foreach my $k1 (keys %$new_hash) {

        foreach my $k2 (keys %{ $$new_hash{$k1} }) {
            next if (($enonly) && ($$new_hash{$k1}{$k2}{'rule'} =~ /^\s*#/));
            if (!defined $$old_hash{$k1}{$k2}{'rule'}) {
                my $msg_holder = $$new_hash{$k1}{$k2}{'rule'};
                if ($msg_holder =~ /msg:"[^"]+";/i) {
                    $msg_holder = $&;
                    $msg_holder =~ s/msg:"//;
                    $msg_holder =~ s/";//;
                }
                else { $msg_holder = "Unknown MSG" }
                push(@newsids, "$msg_holder ($k1:$k2)");
            }
            $rt++ unless defined $$old_hash{$k1}{$k2}{'rule'};
            next  unless defined $$new_hash{$k1}{$k2}{'rule'};
            if ($$new_hash{$k1}{$k2}{'rule'} =~ /^\s*(alert|pass)/) {
                $enabled++;
            }
            elsif ($$new_hash{$k1}{$k2}{'rule'} =~ /^\s*drop/) {
                $dropped++;
            }
            elsif (
                $$new_hash{$k1}{$k2}{'rule'} =~ /^\s*#*\s*(alert|drop|pass)/)
            {
                $disabled++;
            }
        }
    }
    foreach my $k1 (sort keys %$old_hash) {
        for my $k2 (sort keys %{ $$old_hash{$k1} }) {
            next if defined $$new_hash{$k1}{$k2}{'rule'};
            next
                if (($enonly) && ($$old_hash{$k1}{$k2}{'rule'} =~ /^\s*#/));
            my $msg_holder = $$old_hash{$k1}{$k2}{'rule'};
            if ($msg_holder =~ /msg:"[^"]+";/) {
                $msg_holder = $&;
                $msg_holder =~ s/msg:"//;
                $msg_holder =~ s/";//;
            }
            else { $msg_holder = "Unknown MSG" }
            push(@delsids, "$msg_holder ($k1:$k2)");
            $dt++;
        }
    }
    if (%$blocklist_hash) {
        $ips = keys(%$blocklist_hash);
    }
    if (-f $changelog) {
        open(WRITE, '>>', $changelog) || croak "$changelog $!\n";
    }
    else {
        open(WRITE, '>', $changelog) || croak "$changelog $!\n";
        print WRITE
            "-=BEGIN PULLEDPORK SNORT RULES CHANGELOG, Tracking started on "
            . gmtime(time)
            . " GMT=-\n\n\n";
    }
    print WRITE "\n-=Begin Changes Logged for " . gmtime(time) . " GMT=-\n";
    if ($Process) {
        print WRITE "\nNew Rules\n" if @newsids;
        @newsids = sort(@newsids);
        @delsids = sort(@delsids);
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
        print WRITE "\tTotal:-----"
            . ($enabled + $disabled + $dropped) . "\n";
    }
    else { print WRITE "\nNo Rule Changes\n"; }
    if ($bmatch) {
        print WRITE "\nIP Blocklist Stats\n\tTotal IPs:-----$ips\n" if $ips;
    }
    else { print WRITE "\nNo IP Blocklist Changes\n"; }
    print WRITE "\n-=End Changes Logged for " . gmtime(time) . " GMT=-\n";
    close(WRITE);

    if (!$Quiet) {
        print "\tDone\n";
        if ($Process) {
            print "Rule Stats...\n";
            print "\tNew:-------$rt\n";
            print "\tDeleted:---$dt\n";
            print "\tEnabled Rules:----$enabled\n";
            print "\tDropped Rules:----$dropped\n";
            print "\tDisabled Rules:---$disabled\n";
            print "\tTotal Rules:------" . ($enabled + $dropped + $disabled);
        }
        else { print "\nNo Rule Changes\n"; }
        if ($bmatch) {
            print "\nIP Blocklist Stats...\n\tTotal IPs:-----$ips\n" if $ips;
        }
        else { print "\nNo IP Blocklist Changes\n"; }
        print "\nDone\n";
        print "Please review $sid_changelog for additional details\n"
            if $sid_changelog;
    }
    undef @newsids;
    undef @delsids;
}

## Trim it up, loves the trim!
sub trim {
    my ($trimmer) = @_;
    if ($trimmer) {
        $trimmer =~ s/^\s*//;
        $trimmer =~ s/\s*$//;
        return $trimmer;
    }
}

## Does it hurt when I slash you?
sub slash {
    my ($operation, $string) = @_;
    if ($operation == 0 && $string =~ /\/$/ && $string ne "") {
        $string =~ s/\/$//;
    }
    elsif ($operation == 1 && $string !~ /\/$/ && $string ne "") {
        $string = $string . "/";
    }
    return $string;
}

## Test the intermediate levels with exists to prevent unintended autovivification
sub safe_defined {
    my ($h, @keys) = @_;
    foreach my $k (@keys) {
        return unless ref $h eq 'HASH';
        return unless exists $h->{$k};
        $h = $h->{$k};
    }
    return defined $h;
}

## uh, yeah
sub Version {
    print("PulledPork v$VERSION - $HUMOR\n\n");
    exit(0);
}

## find the snort version baby!
sub snort_version {
    my $cmd = shift;
    $cmd .= " -V";
    my $version;
    open(FH, "$cmd 2>&1 |");
    while (<FH>) {
        next unless $_ =~ /Version/;
        if ($_ =~ /\d+\.\d+\.\d+\.\d+/) {
            $version = $&;
        }
        elsif ($_ =~ /\d+\.\d+\.\d+(?!\.)/) {
            $version = $& . ".0";
        }
    }
    close(FH);
    return $version;
}

## our arch
sub get_arch {
    my $cmd = "uname -a";
    open(FH, "$cmd |");
    my $arch;
    while (<FH>) {
        next unless $_ =~ /(i386|x86-64|x86_64|i686|amd64)/i;
        $arch = $&;
        $arch =~ s/_/-/;
        $arch =~ s/i686/i386/;
        $arch =~ s/amd64/x86-64/;
    }
    close(FH);
    return $arch;
}

## log to syslog
sub syslogit {
    my ($level, $msg) = @_;

    openlog('pulledpork', 'ndelay,pid', 'local0');
    syslog($level, $msg);
    closelog;
}

## Create some backup and archive foo!
sub archive {
    my ($data, $filename) = @_;
    my @records;
    my $compression = "COMPRESS_GZIP";
    $filename .= "." . time() . ".tgz";
    print "Creating backup at: $filename\n" unless $Quiet;
    foreach my $record (@$data) {
        if (-f $record) {
            print "\tAdding file: $record\n" if $Verbose && !$Quiet;
            push(@records, $record);
        }
        elsif (-d $record) {
            print "\tAdding dir: $record\n" if $Verbose && !$Quiet;
            find(\&archive_wanted, $record);
        }
    }
    print "\tWriting Archive: $filename - may take several minutes!\n"
        if $Verbose && !$Quiet;
    Archive::Tar->create_archive($filename, $compression, @records);
}

## Define what we will find for the archive sub when dir is found!
sub archive_wanted {
    return unless -f $_;
    print "\tAdding file: $File::Find::name\n" if $Verbose == 2 && !$Quiet;
    push(@records, $File::Find::name);
}

## Create ignore_files from conf file
sub get_ignore_files {
    my ($ignore_conf_file) = @_;
    my $ignore_list;

    print "\tReading ignore_file: $ignore_conf_file\n";

    # Read ignore file and exclude comments/blank lines
    open(FH, '<', $ignore_conf_file)
        || croak "Couldn't read $ignore_conf_file $!\n";
    while (<FH>) {
        chomp;
        s/#.*//;
        if (!/^\s*$/) { $ignore_list .= "$_," }
    }
    close FH;
    $ignore_list =~ s/,\s*$//g;
    return $ignore_list;
}

## Verify if directories or files actually exist
sub check_file_dir {
    my ($filedir_input) = @_;
    my ($dir_check, $file_check) = ($filedir_input =~ /(^.*)(?:\/|\\)(.*)$/);
    if (!-d $dir_check && !-w $file_check) {
        croak
            "Error: $dir_check does not exist, please create this directory\n";
        exit(1);
    }
}

###
### Main here, let's get on with it already
###

if ($#ARGV == -1) {
    Help(
        "Please read the README for runtime options and configuration documentation"
    );
}

## Lets grab any runtime values and insert into our variables using getopt::long
GetOptions(
    "a!"     => \$Auto,
    "b=s"    => \$sidmod{drop},
    "c=s"    => \$Config_file,
    "C=s"    => \$Snort_config,
    "d!"     => \$Hash,
    "D=s"    => \$Distro,
    "E!"     => \$enonly,
    "e=s"    => \$sidmod{enable},
    "g!"     => \$grabonly,
    "H=s"    => \$SigName,
    "h=s"    => \$sid_changelog,
    "i=s"    => \$sidmod{disable},
    "I=s"    => \$ips_policy,
    "k!"     => \$keep_rulefiles,
    "K=s"    => \$rule_file_path,
    "l!"     => \$Syslogging,
    "L=s"    => \$local_rules,
    "M=s"    => \$sidmod{modify},
    "m=s"    => \$sid_msg_map,
    "n!"     => \$NoDownload,
    "o=s"    => \$Output,
    "O=s"    => \$oinkcode,
    "p=s"    => \$Snort_path,
    "P!"     => \$Process,
    "q"      => \$Quiet,
    "R!"     => \$rstate,
    "S=s"    => \$Snort,
    "s=s"    => \$Sorules,
    "T!"     => \$Textonly,
    "u=s"    => \@base_url,
    "V!"     => sub { Version() },
    "v+"     => \$Verbose,
    "help|?" => sub { Help() },
    "w"      => \$skip_verify,
    "W"      => \$proxy_workaround
);

## Fly piggy fly!
pulledpork() if !$Quiet;

# Dump our variables for verbose/debug output

if (!$Config_file) { Help("No configuration file specified"); }

# Call the subroutine to fetch config values
parse_config_file($Config_file, \%Config_info);

if ($Verbose && !$Quiet) {
    print "Config File Variable Debug $Config_file\n";
    foreach $Config_key (keys %Config_info) {
        if ($Config_info{$Config_key}) {
            print "\t$Config_key = $Config_info{$Config_key}\n";
        }
    }

}

if (exists $Config_info{'version'}) {
    croak "You are not using the current version of pulledpork.conf!\n",
        "Please use the version of pulledpork.conf that shipped with $VERSION!\n\n"
        if $Config_info{'version'} ne "$VERSION";
}
else {
    croak
        "You are not using the current version of pulledpork.conf!\nPlease use the version that shipped with $VERSION!\n\n";
}

# Check to see if we have command line inputs, if so, they super-seed any config file values!
# We also begin sub execution here

$pid_path     = ($Config_info{'pid_path'}) if exists $Config_info{'pid_path'};
$ignore_files = ($Config_info{'ignore'})   if exists $Config_info{'ignore'};

# Allow ignores to be specified in a file, supercedes the regular ignore config option
if (exists $Config_info{'ignore_file'}) {
    $ignore_files = get_ignore_files($Config_info{'ignore_file'});
}

if ($rule_file_path) {
    $keep_rulefiles = 1;
}

$sid_msg_version = $Config_info{'sid_msg_version'};

if ($keep_rulefiles && defined $Config_info{'out_path'} && !$rule_file_path) {
    $rule_file_path = $Config_info{'out_path'};
}

if ($rule_file_path) {
    $rule_file_path = slash(1, "$rule_file_path");
}

if (!$ips_policy && defined $Config_info{'ips_policy'}) {
    $ips_policy = $Config_info{'ips_policy'};
}

if (!$block_list && defined $Config_info{'block_list'}) {
    $block_list = $Config_info{'block_list'};
    check_file_dir($block_list);
}

if (!$sidmod{enable} && defined $Config_info{'enablesid'}) {
    $sidmod{enable} = $Config_info{'enablesid'};
}

if (!$sidmod{modify} && defined $Config_info{'modifysid'}) {
    $sidmod{modify} = $Config_info{'modifysid'};
}

if (!$sidmod{drop} && defined $Config_info{'dropsid'}) {
    $sidmod{drop} = $Config_info{'dropsid'};
}

if (!$sidmod{disable} && defined $Config_info{'disablesid'}) {
    $sidmod{disable} = $Config_info{'disablesid'};
}

my @sidact = ('enable', 'drop', 'disable');

if (defined $Config_info{'state_order'}) {
    (@sidact) = split(/,/, $Config_info{'state_order'});
}

if (!@base_url) {
    @base_url = @{ $Config_info{'rule_url'} };
    if (!@base_url) {
        Help(
            "You need to specify one rule_url at a minimum to fetch the rules files from!\n"
        );
    }
}

if (!$Output) {
    $Output = ($Config_info{'rule_path'});
    check_file_dir($Output);
}

if (!$Output && !($keep_rulefiles && $rule_file_path)) {
    Help("You need to specify an output rules file or output path!");
}

$Output = slash(0, $Output) if $Output;

if (!$Sorules) {
    $Sorules = ($Config_info{'sorule_path'});
}
$Sorules = slash(1, $Sorules) if $Sorules;

undef $Sostubs if ($Textonly);
undef $Sorules if ($Textonly);

if (!$Distro) {
    $Distro = ($Config_info{'distro'});
}

if (!$Snort) {
    $Snort = ($Config_info{'snort_version'});
}

if (!$Snort_path) {
    $Snort_path = ($Config_info{'snort_path'});
    $Snort      = snort_version($Snort_path) if (!$Snort && -B $Snort_path);
    $arch       = get_arch();
    $Textonly   = 1 unless $Snort;
}

# Check if version begins with 3
if (ord($Snort) == 51) {
	$Snortv3 = 1;
	if ($arch) {$arch =~ s/x86-64/x64/;}
}

if (!$local_rules && ($Config_info{'local_rules'})) {
    $local_rules = ($Config_info{'local_rules'});
}
elsif (!$local_rules && !($Config_info{'local_rules'})) {
    $local_rules = 0;
}

if (!$Snort_config) {
    $Snort_config = ($Config_info{'config_path'});
}

if (!$sid_msg_map) {
    $sid_msg_map = ($Config_info{'sid_msg'});
}
if (!$sid_changelog) {
    $sid_changelog = ($Config_info{'sid_changelog'});
}

if (!$ips_policy) {
    $ips_policy = "Disabled";
}

if ($Verbose && !$Quiet) {
    print "MISC (CLI and Autovar) Variable Debug:\n";
    if ($Process)        { print "\tProcess flag specified!\n"; }
    if ($arch)           { print "\tarch Def is: $arch\n"; }
    if ($oSystem)        { print "\tOperating System is: $oSystem\n"; }
    if ($CAFile)         { print "\tCA Certificate File is: $CAFile\n"; }
    if ($Config_file)    { print "\tConfig Path is: $Config_file\n"; }
    if ($Distro)         { print "\tDistro Def is: $Distro\n"; }
    if ($keep_rulefiles) { print "\tKeep rulefiles flag is Set\n"; }
    if ($rule_file_path) { print "\tKeep rulefiles path: $rule_file_path\n"; }
    if ($enonly)         { print "\tWrite ONLY enabled rules flag is Set\n"; }
    if ($grabonly) { print "\tgrabonly Flag is Set, only gonna download!"; }

    if ($Hash) {
        print
            "\tNo MD5 Flag is Set, uhm, ok? I'm gonna fetch the latest file no matter what!\n";
    }
    if ($ips_policy)  { print "\t$ips_policy policy specified\n"; }
    if ($local_rules) { print "\tlocal.rules path is: $local_rules\n"; }
    if ($NoDownload)  { print "\tNo Download Flag is Set\n"; }
    if ($Output)      { print "\tRules file is: $Output\n"; }
    if ($rstate)      { print "\tReturn State flag is Set\n"; }
    if ($rule_file)   { print "\tRule File is: $rule_file\n"; }
    if ($sidmod{disable}) {
        print "\tPath to disablesid file: $sidmod{disable}\n";
    }
    if ($sidmod{drop}) { print "\tPath to dropsid file: $sidmod{drop}\n"; }
    if ($sidmod{enable}) {
        print "\tPath to enablesid file: $sidmod{enable}\n";
    }
    if ($sidmod{modify}) {
        print "\tPath to modifysid file: $sidmod{modify}\n";
    }
    if ($sid_changelog) {
        print "\tsid changes will be logged to: $sid_changelog\n";
    }
    if ($sid_msg_map) {
        print "\tsid-msg.map Output Path is: $sid_msg_map\n";
    }
    if ($SigName)      { print "\tSending signal Flag is Set: $SigName\n"; }
    if ($Snort)        { print "\tSnort Version is: $Snort\n"; }
    if ($Snortv3)        { print "\tSnort V3 detected & processing enabled\n"; }
    if ($Snort_config) { print "\tSnort Config File: $Snort_config\n"; }
    if ($Snort_path)   { print "\tSnort Path is: $Snort_path\n"; }
    if ($Sorules)      { print "\tSO Output Path is: $Sorules\n"; }
    if ($Sostubs)      { print "\tWill process SO rules\n"; }
    if ($Syslogging)   { print "\tLogging Flag is Set\n"; }
    if ($Textonly)     { print "\tText Rules only Flag is Set\n"; }
    if ($Verbose == 2) { print "\tExtra Verbose Flag is Set\n"; }
    if ($Verbose)      { print "\tVerbose Flag is Set\n"; }
    if ($skip_verify)  { print "\tSSL Hostname Verification disabled\n"; }

    if ($proxy_workaround) {
        print "\tLWP Workaround is set for Proxy connections\n";
    }
    if ($ignore_files) { print "\tFile(s) to ignore = $ignore_files\n"; }
    if (@base_url)     { print "\tBase URL is: @base_url\n"; }
}

# We need a temp path to work with the files while we do magics on them.. make sure you have plenty
# of space in this path.. ~200mb is a good starting point
$temp_path = ($Config_info{'temp_path'});
if (!$temp_path) {
    Help("You need to specify a valid temp path, check permissions too!");
}
$temp_path = slash(1, $temp_path);
if (!-d $temp_path) {
    Help("Temporary file path $temp_path does not exist.\n");
}

# Validate sid_msg_map version
Help(
    "Please specify version 1 or 2 for sid_msg_version in your config file\n")
    unless $sid_msg_version =~ /(1|2)/;


# set some UserAgent and other connection configs
$ua->agent("PulledPork v$VERSION");
$ua->show_progress(1) if ($Verbose && !$Quiet);

# check to see if SSL verfication is disabled
if ($skip_verify) {
    $ua->ssl_opts(verify_hostname => 0);
}


# New Settings to allow proxy connections to use proper SSL formating - Thx pkthound!
$ua->timeout(60);
$ua->cookie_jar({});
$ua->protocols_allowed(['http', 'https']);
$ua->proxy(['http'],  $ENV{http_proxy})  if $ENV{http_proxy};
$ua->proxy(['https'], $ENV{https_proxy}) if $ENV{https_proxy};

# Pull in our env vars before we load any of the modules!
BEGIN {
    my $proxy = $ENV{http_proxy};
    if ($proxy) {

        #Let's handle proxy variables with username / passphrase in them!
        if ($proxy =~ /^(http|https):\/\/([^:]+):([^:]+)@(.+)$/i) {
            my $proxytype = $1;
            my $proxyuser = $2;
            my $proxypass = $3;
            my $proxyaddy = $4;

            $ENV{HTTP_PROXY}           = "$proxytype://$proxyaddy";
            $ENV{HTTP_PROXY_USERNAME}  = $proxyuser;
            $ENV{HTTP_PROXY_PASSWORD}  = $proxypass;
            $ENV{HTTPS_PROXY}          = "$proxytype://$proxyaddy";
            $ENV{HTTPS_PROXY_USERNAME} = $proxyuser;
            $ENV{HTTPS_PROXY_PASSWORD} = $proxypass;
        }
        else {
            $ENV{HTTPS_PROXY} = $proxy;
            $ENV{HTTP_PROXY}  = $proxy;
        }
    }
    undef $proxy;
    $proxy = $ENV{https_proxy};    #check for https_proxy env var
    if ($proxy) {

        #Let's handle proxy variables with username / passphrase in them!
        if ($proxy =~ /^(http|https):\/\/([^:]+):([^:]+)@(.+)$/i) {
            my $proxytype = $1;
            my $proxyuser = $2;
            my $proxypass = $3;
            my $proxyaddy = $4;

            $ENV{HTTPS_PROXY}          = "$proxytype://$proxyaddy";
            $ENV{HTTPS_PROXY_USERNAME} = $proxyuser;
            $ENV{HTTPS_PROXY_PASSWORD} = $proxypass;
        }
        else {
            $ENV{HTTPS_PROXY} = $proxy;
        }
    }
}

if ($Verbose == 2) {
    $ENV{HTTPS_DEBUG} = 1;
    $ENV{HTTP_DEBUG}  = 1;
    print "\n\nMY HTTPS PROXY = $ENV{HTTPS_PROXY}\n"
        if ($ENV{HTTPS_PROXY} && !$Quiet);
    print "\n\nMY HTTP PROXY = $ENV{HTTP_PROXY}\n"
        if ($ENV{HTTP_PROXY} && !$Quiet);
}

# let's fetch the most recent md5 file then compare and do our foo
if (@base_url && -d $temp_path) {

    if (-d $temp_path . "tha_rules") {
        print
            "\tdoh, we need to perform some cleanup ... an unclean run last time?\n"
            if ($Verbose && !$Quiet);
        temp_cleanup($temp_path);
    }

    if (!$NoDownload) {

        # Crate a local hash that we will iterate through later for processing
        my $filelist = ();
        my $blk      = 0;
        my $Snortv   = "";

        # Iterate through all of our urls and check md5 then process accordingly etc...
        foreach (@base_url) {
            undef $Hash if ($Hash && $Hash == 2);

            #undef $Process if ($Process && $Process ==2);
            my ($base_url, $rule_file, $oinkcode) = split(/\|/, $_);
            croak
                "You need to define an oinkcode, please review the rule_url section of the pulledpork config file!\n"
                unless $oinkcode;
            croak(
                "please define the rule_url correctly in the pulledpork.conf\n"
            ) unless defined $base_url;
            croak(
                "please define the rule_url correctly in the pulledpork.conf\n"
            ) unless defined $rule_file;

            if ($base_url =~ /[^labs]\.snort\.org/i) {
                $prefix = "VRT-";
                unless ($rule_file =~ /snortrules-snapshot-\d{4,6}\.tar\.gz/)
                {
                    croak(
                        "The specified Snort binary does not exist!\nPlease correct the value or specify the FULL",
                        " rules tarball name in the pulledpork.conf!\n"
                    ) unless $Snort;
                    $Snortv = $Snort;
                    $Snortv =~ s/\.//g;
                    $rule_file = "snortrules-snapshot-$Snortv.tar.gz";
                }
            }
            elsif ($base_url =~ /(emergingthreats.net)/) {
                $prefix = "ET-";

                # These have to be handled separately, as emerginthreatspro will
                # support a full version, but emergingthreats only supports the
                # major and minor version.
                # Currently this is a check that the version
                # is in fact a Snort version, where Suricata
                # will require suricata to be included in the version
                # to work with suricata rules. Current open set uses
                # only the first part of the version.
                if ($Snort =~ /^\d+\.\d+\.\d+\.\d+/) {
                    $Snortv = $Snort;
                    $Snortv =~ s/^(\d+\.\d+)\.\d+\.\d/$1.0/;
                    $base_url .= "$oinkcode/snort-$Snortv/";
                }
                elsif ($Snort =~ /suricata/i) {

                    # Assumption here, this will need to be fixed
                    # as the open ruleset does not handle suricata
                    # versions
                    $base_url .= "$oinkcode/$Snort/";
                }
            }
            elsif ($base_url =~ /emergingthreatspro.com/) {
                $prefix = "ET-";

                # These have to be handled separately, as emerginthreatspro will
                # support a full version, but emergingthreats only supports the
                # major and minor version
                if ($Snort =~ /^\d+\.\d+\.\d+\.\d+/) {
                    $Snortv = $Snort;
                    $Snortv =~ s/^(\d+\.\d+)\.\d+\.\d/$1.0/;
                    $base_url .= "$oinkcode/snort-$Snortv/";
                }
                elsif ($Snort =~ /suricata/i) {

                    # Assumption here, this will need to be fixed
                    # as the open ruleset does not handle suricata
                    # versions
                    $base_url .= "$oinkcode/$Snort/";
                }
            }
            elsif ($base_url =~ /snort\.org.+community/) {
                $prefix = "Snort-Community-";
            }
            elsif ($base_url =~ /secureworks/) {
                $prefix = "SecureWorks-";
                $base_url .= "$oinkcode/"
                    unless $base_url =~ /\x2F$oinkcode\x2F/;
            }

            $prefix = "Custom-" unless $prefix;

            $Hash = 2
                unless $base_url
                =~ /(secureworks|emergingthreats|[^labs]\.snort\.org)|snort\.org.+community/;
            if ($rule_file =~ /IPBLOCKLIST/) {
                $Hash = 2;
                $rule_file .= $blk++;
            }

            if ($rule_file =~ /RULEFILE/) {
                $Hash = 2;
            }

            if (!$Hash) {
                $md5 = md5file($oinkcode, $rule_file, $temp_path, $base_url);
            }

            # and now lets determine the md5 of the last saved rules file if it exists
            if (-f "$temp_path" . "$rule_file" && !$Hash) {
                $rule_digest = md5sum($rule_file, $temp_path);
            }
            else {    # the file didn't exsist so lets get it
                rulefetch($oinkcode, $rule_file, $temp_path, $base_url);
                $Process = 1 unless $rule_file =~ /IPBLOCKLIST/;
                if (-f "$temp_path" . "$rule_file" && !$Hash) {
                    $rule_digest = md5sum($rule_file, $temp_path);
                }
            }

            # Don't need to perform the following on the IP blocklist stuff...
            next if $rule_file =~ /IPBLOCKLIST/;

            # Stuff it all into a hash for use in a bit...
            $filelist->{$rule_file} = {
                'oinkcode'     => $oinkcode,
                'temp_path'    => $temp_path,
                'Hash'         => $Hash,
                'base_url'     => $base_url,
                'md5'          => $md5,
                'rule_digest'  => $rule_digest,
                'Distro'       => $Distro,
                'arch'         => $arch,
                'Snort'        => $Snort,
                'Snortv3'      => $Snortv3,
                'Sorules'      => $Sorules,
                'ignore_files' => $ignore_files,
                'prefix'       => $prefix,
                'Process'      => $Process,
                'hmatch'       => $hmatch
            };

            # compare the online current md5 against against the md5 of the rules file on system
            $hmatch = compare_md5(
                $oinkcode, $rule_file, $temp_path,   $Hash,
                $base_url, $md5,       $rule_digest, $Distro,
                $arch,     $Snort,     $Sorules,     $ignore_files,
                $prefix,   $Process,   $hmatch,      $filelist
            );
        }

        # If any of our rules tarballs are new or changed then we need to process all of them
        if (($filelist->{EXTRACT} && $filelist->{EXTRACT} == 1) || $Process) {
            foreach (keys %{$filelist}) {
                next if $_ eq "EXTRACT";
                $Process = 1;

                if ($filelist->{$_}{oinkcode} !~ "RULEFILE") {
                    rule_extract(
                        $_,
                        $filelist->{$_}{temp_path},
                        $filelist->{$_}{Distro},
                        $filelist->{$_}{arch},
                        $filelist->{$_}{Snort},
                        $filelist->{$_}{Sorules},
                        $filelist->{$_}{ignore_files},
                        $filelist->{$_}{prefix},
                        $filelist->{$_}{Snortv3}
                    );
                }
            }
        }
    }

    # Only process a local rules tarball
    if ($NoDownload && !$grabonly) {
        foreach (@base_url) {
            my ($base_url, $rule_file) = split(/\|/, $_);
            next if $rule_file =~ /IPBLOCKLIST/;
            if ($base_url =~ /[^labs]\.snort\.org/i) {
                $prefix = "VRT-";
                unless ($rule_file =~ /snortrules-snapshot-\d{4,6}\.tar\.gz/)
                {
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
                unless (-f "$temp_path/$rule_file");
            $prefix = "ET-"
                if $base_url
                =~ /(emergingthreats.net|emergingthreatspro.com)/;
            $prefix = "Snort-Community-"
                if $base_url =~ /snort\.org.+community/;
            rule_extract($rule_file, $temp_path, $Distro,
                $arch, $Snort, $Sorules, $ignore_files, $prefix, $Snortv3)
                if !$grabonly;
        }
    }

    # Read our rules and stuff them into a hash
    if (   ($Output || ($keep_rulefiles && $rule_file_path))
        && !$grabonly
        && $Process)
    {
        read_rules(\%rules_hash, "$temp_path" . "tha_rules/", $local_rules);
    }

    #Process things differently for Snort 3+ in future
    if ($Snort =~ /3\.\d\.\d\.\d/) {
        if (!$Quiet) {
            print "Snort 3.0 detected, future Snort 3.0 processing\n";
        }
    }

    # If we are using SO rules, generate the stubs and then stuff them into a hash
    if (   $Sorules
        && -e $Sorules
        && $Distro
        && $Snort
        && !$Textonly
        && !$grabonly
        && $Process)
    {
        gen_stubs($Snort_path, $Snort_config,
            "$temp_path" . "tha_rules/so_rules/", $Snortv3, $Sorules);
        read_rules(\%rules_hash, "$temp_path" . "tha_rules/so_rules/",
            $local_rules);
    }
}
else { Help("Check your oinkcode, temp path and freespace!"); }

# Read our old rules so that we can determine what is new / changed / deleted
if (   ($Output || ($keep_rulefiles && $rule_file_path))
    && !$grabonly
    && $Process)
{
    if ($sid_changelog && defined $Output && -f $Output && !$keep_rulefiles) {
        read_rules(\%oldrules_hash, "$Output", $local_rules);
    }
    if ($sid_changelog && $keep_rulefiles && -d $rule_file_path) {
        read_rules(\%oldrules_hash, "$rule_file_path", $local_rules);
    }

    #print Dumper(%oldrules_hash);
}

# Clean up temp path
if (-d $temp_path) {
    temp_cleanup();
}


# Process our blocklist data.. need to add a conditional where if we are not linux, we don't
# use the control socket (linux only)
if ($block_list && %blocklist && !$NoDownload) {
    $bmatch = blocklist_write(\%blocklist, $block_list);
    iprep_control($Config_info{'snort_control'}, $Config_info{'IPRVersion'})
        if $bmatch;
}

# Set our rule states, based on config files and specified base policy, also set our flowbit dependencies
if (   ($Output || ($keep_rulefiles && $rule_file_path))
    && !$grabonly
    && $Process)
{
    if ($ips_policy ne "Disabled") {
        policy_set($ips_policy, \%rules_hash);
    }

    if ($sidmod{modify} && -f $sidmod{modify}) {
        modify_sid(\%rules_hash, $sidmod{modify});
    }

    foreach (@sidact) {
        if ($sidmod{$_} && -f $sidmod{$_}) {
            modify_state($_, $sidmod{$_}, \%rules_hash, $rstate);
        }
        elsif ($sidmod{$_} && !-f $sidmod{$_}) {
            carp "Unable to read: $sidmod{$_} - $!\n";
        }
    }

    print "Setting Flowbit State....\n"
        if (!$Quiet);

    my $fbits = 1;
    while ($fbits > 0) {
        $fbits = flowbit_set(\%rules_hash);
    }
    print "\tDone\n"
        if (!$Quiet);

    if ($Output && $Process && !$keep_rulefiles) {
        rule_write(\%rules_hash, $Output, $enonly);
    }

    if ($keep_rulefiles && $rule_file_path && $Process) {
        rule_category_write(\%rules_hash, $rule_file_path, $enonly,
            $local_rules);
    }

    if ($sid_msg_map && $Process) {
        sid_msg(\%rules_hash, \%sid_msg_map, $enonly);
        sid_write(\%sid_msg_map, $sid_msg_map, $sid_msg_version);
    }

    if ($SigName && $pid_path ne "" && $Process) {

        # This may need to be changed, but for now, error out
        # if the signal name is not SIGHUP or SIGUSR2
        if ($SigName eq "SIGHUP" || $SigName eq "SIGUSR2") {
            send_signal($SigName, $pid_path) unless $Sostubs;
            print "WARNING, cannot send signal if also processing SO rules\n",
                "\tsee README.SHAREDOBJECTS\n", "\tor use -T flag!\n"
                if ($Sostubs && !$Quiet);
        }
        else {
            carp "Bad signal name used: $SigName - $!\n";
        }
    }

    if ($Config_info{backup}) {
        @records = split(/,/, $Config_info{backup});
        archive(\@records, $Config_info{backup_file})
            if $Config_info{backup_file};
        if ($Verbose) {
            print
                "\tWARN - Unable to create a backup without defining backup_file in config!\n",
                unless $Config_info{backup_file};
        }
        print "\tDone\n" unless $Quiet;
    }
}

if (
    $sid_changelog
    && (   (defined $Output && -f $Output)
        || ($keep_rulefiles && -d $rule_file_path))
    )
{
    changelog($sid_changelog, \%rules_hash, \%oldrules_hash, \%blocklist,
        $ips_policy, $enonly, $hmatch, $bmatch);
}

print("Fly Piggy Fly!\n")                            if !$Quiet;
syslogit('warning|local0', "INFO: Finished Cleanly") if $Syslogging;

__END__
