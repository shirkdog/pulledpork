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
use LWP::Simple;
use Digest::MD5;
use File::Path;
use Getopt::Long qw(:config no_ignore_case bundling);
use Archive::Tar;  # Finally, right!
use POSIX qw(:errno_h);  
use Switch;


#we are gonna need these!
my ($oinkcode,$temp_path,$rule_file);

my $VERSION = "Pulled_Pork v0.4.0 Dev (Drunken Leprechaun)";

# routine to grab our config from the defined config file
sub parse_config_file {
    my ($FileConf, $Config_val) = @_;
    my ($config_line, $Name, $Value);

    if (!open (CONFIG, "$FileConf")) {
        print "ERROR: Config file not found : $FileConf";
        exit(0);
    }
    open (CONFIG, "$FileConf");
    while (<CONFIG>) {
        $config_line=$_;
        chomp($config_line);          # Get rid of the trailling \n
        $config_line=trim($config_line);
        if ( ($config_line !~ /^#/) && ($config_line ne "") ){    # Ignore lines starting with # and blank lines
            ($Name, $Value) = split (/=/, $config_line);          # Split each line into name value pairs
            $$Config_val{$Name} = $Value;                             # Create a hash of the name value pairs
        }
    }

    close(CONFIG);

}

my ($Verbose,$Logging,$Hash,$ALogger,$Config_file,$Sorules,$Auto);
my ($Output,$Distro,$Snort,$Sostubs,$sid_changelog);
my ($Snort_config,$Snort_path,$Textonly,$SID_conf,$DISID_conf);
my ($pid_path,$SigHup,$NoDownload,$sid_msg_map,$base_url);
my ($ips_policy,$enable_conf,$local_rules,$arch,$ignore_files);

$Verbose = 0;
undef($Logging);
undef($Hash);
undef($ALogger);

my %rules_hash = ();
my %oldrules_hash = ();
my %sid_msg_map = ();

## Help routine.. display help to stdout then exit
sub Help
{
my $msg=@_;
if ($msg) { print "\nERROR: $msg\n"; }

print<<__EOT;
  Usage: $0 [-lvvVdnHTn? -help] -c <config filename> -o <rule output path>
   -O <oinkcode> -s <so_rule output directory> -D <Distro> -S <SnortVer>
   -p <path to your snort binary> -C <path to your snort.conf> -t <sostub output path>
   -h <changelog path> -I (security|connectivity|balanced)
  
   Options:
   -c Where the pulledpork config file lives.
   -i Where the disablesid config file lives.
   -b Where the dropsid config file lives.
   -e Where the enablesid config file lives.
   -o Where do you want me to put generic rules file?
   -L Where do you want me to read your local.rules for inclusion in sid-msg.map
   -h path to the sid_changelog if you want to keep one?
   -f What snort rules tarball do you want to fetch 
      (i.e. snortrules-snapshot-2.8_s.tar.gz)
   -u Where do you want me to pull the rules tarball from 
      (ET, Snort.org, see pulledpork config base_url option for value ideas)
   -O What is your Oinkcode?
   -I Specify a base ruleset( -I security,connectivity,or balanced, see README.RULESET)
   -T Process text based rules files only, i.e. DO NOT process so_rules
   -m where do you want me to put the sid-msg.map file?
   -s Where do you want me to put the so_rules?
   -S Specify your Snort version
      Valid options for this value 2.8.0.1,2.8.0.2,2.8.1,2.8.2,2.8.2.1,2.8.2.2,
	  2.8.3,2.8.3.1,2.8.3.2,2.8.4,2.8.4.1,2.8.5
   -C Path to your snort.conf
   -p Path to your Snort binary
   -t Where do you want me to put the so_rule stub files? ** Thus MUST be uniquely 
      different from the -o option value
   -D What Distro are you running on, for the so_rules
      Valid Distro Types=CentOS-4.6,CentOS-5.0,Debian-Lenny,FC-5,FC-9,FreeBSD-7.0,
	  RHEL-5.0,Ubuntu-6.01.1,Ubuntu-8.04
   -a Specify the arch that you are running valid options here are i386 or x86-64
   -l Log information to logger rather than stdout messages.  **not yet implemented**
   -v Verbose mode, you know.. for troubleshooting and such nonsense.
   -vv EXTRA Verbose mode, you know.. for in-depth troubleshooting and other such nonsense.
   -d Do not verify signature of rules tarball, i.e. downloading fron non VRT or ET locations.
   -H Send a SIGHUP to the pids listed in the config file
   -n Do everything other than download of new files (disablesid, etc)
   -V Print Version and exit
   -help/? Print this help info.

__EOT

    exit(0);
}

## OMG We MUST HAVE FLYING PIGS!
sub pulledpork
{

print<<__EOT;

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
my $md5 = "";

## Fly piggy fly!
pulledpork();
if($#ARGV==-1){Help("Please read the README for runtime options and configuration documentation");}

# subroutine to cleanup the temp rubbish!!!
sub temp_cleanup
{
    my $remove = rmtree ( $temp_path."tha_rules" );
	print "\tremoved $remove temporary snort files or directories from $temp_path"."tha_rules!\n" if $Verbose;
}

# subroutine to extract the files to a temp path so that we can do what we need to do.. 
sub rule_extract
{	
    my ($rule_file,$temp_path,$Distro,$arch,$Snort,$Sorules,$ignore) = @_;
	print "Prepping rules for work....\n";
    if ( -d $temp_path."tha_rules") { 
		print "\tdoh, we need to perform some cleanup... an unclean run last time?\n" if $Verbose;
		temp_cleanup($temp_path);
    }
    print "\textracting contents of $temp_path$rule_file...\n" if $Verbose;
    mkpath($temp_path."tha_rules");
    mkpath($temp_path."tha_rules/so_rules");
    my $tar = Archive::Tar->new();
    $tar->read($temp_path.$rule_file);
    my @ignores=split(/,/,$ignore);
    foreach (@ignores) {
		$tar->remove("rules/$_\.rules");
	}
    my @files=$tar->get_files();
    foreach (@files) {
		my $filename = $_->name;
		my $singlefile=$filename;
		if($filename =~ /^rules\/.*\.rules$/) {
			$singlefile=~s/^rules\///;
			$tar->extract_file($filename,$temp_path."/tha_rules/".$singlefile);
			print "\tExtracted: /tha_rules/$singlefile\n" if $Verbose;
		}
		elsif ($Sorules && $filename =~ /^so_rules\/precompiled\/($Distro)\/($arch)\/($Snort)\/.*\.so/ && -d $Sorules) {
			$singlefile=~s/^so_rules\/precompiled\/($Distro)\/($arch)\/($Snort)\///;
			$tar->extract_file($filename,$Sorules.$singlefile);
			print "\tExtracted: $Sorules$singlefile\n" if $Verbose;
		}
	}
	if (!$Verbose) { print "\tDone!\n"; }
}

# subroutine to actually check the md5 values, if they match we move onto file manipulation routines
sub compare_md5
{
    my ($oinkcode,$rule_file,$temp_path,$Hash,$base_url,$md5,$rule_digest,$Distro,$arch,$Snort,$Sorules,$ignore_files) = @_;
	#print "Checking the MD5....\n";
    if ($rule_digest =~ $md5 && !$Hash){
	if ($Verbose)
	    { print "\tThe MD5 for $rule_file matched $md5\n\tso I'm not gonna download the rules file again suckas!\n"; }
	    if (!$Verbose) { print "\tThey Match\n\tDone!\n"; }
		rule_extract($rule_file,$temp_path,$Distro,$arch,$Snort,$Sorules,$ignore_files);
	} 
	elsif (!$Hash)
	    {
		if ($Verbose)
		    { print "\tThe MD5 for $rule_file did not match the latest digest... so I am gonna fetch the latest rules file!\n"; }
		if (!$Verbose) { print "\tNo Match\n\tDone\n"; }
			rulefetch($oinkcode,$rule_file,$temp_path,$base_url);
                    $rule_digest = md5sum($rule_file,$temp_path);
                    compare_md5 ($oinkcode,$rule_file,$temp_path,$Hash,$base_url,$md5,$rule_digest,$Distro,$arch,$Snort,$Sorules,$ignore_files);
		} 
	else {
            if ($Verbose)
            { print "\tOk, not verifying the digest.. lame, but that's what you specified!\n";
				print "\tSo if the rules tarball doesn't extract properly and this script dies.. it's your fault!\n";}
			if (!$Verbose) { print "\tNo Verify Set\n\tDone!\n"; }
            rule_extract($rule_file,$temp_path,$Distro,$arch,$Snort,$Sorules,$ignore_files);
         }
}

## time to grab the real 0xb33f
sub rulefetch
{
    my ($oinkcode,$rule_file,$temp_path,$base_url) = @_;
    print "Rules tarball download....\n";
	$base_url=slash(0,$base_url);
	my ($getrules_rule);
	if ($Verbose)
	{ print "\tFetching rules file: $rule_file\n";
        if ($Hash) { print "But not verifying MD5\n"; }
         }
    if ($base_url =~ /snort\.org\/pub/i){
		$getrules_rule = getstore("http://www.snort.org/pub-bin/oinkmaster.cgi/".$oinkcode."/".$rule_file,$temp_path.$rule_file);
    }
	else {
		$getrules_rule = getstore($base_url."/".$rule_file,$temp_path.$rule_file);
	}
	if ($getrules_rule==403){print "\tA 403 error occured, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n";}
    die "\tError $getrules_rule when fetching ".$rule_file unless is_success($getrules_rule);
    if ($Verbose)
	{ print ("\tstoring file at: $temp_path$rule_file\n\n"); }
	if (!$Verbose) { "\tDone!\n"; }
}

#subroutine to deterine the md5 digest of the current rules file
sub md5sum
{
    my ($rule_file,$temp_path) = @_;
    open(MD5FILE,"$temp_path$rule_file")
        or die $!;
    binmode(MD5FILE);
    $rule_digest = Digest::MD5->new->addfile(*MD5FILE)->hexdigest;
    close(MD5FILE);
    if($@){
	print $@;
	return "";
    }
    if ($Verbose)
	{ print "\tcurrent local rules file  digest: $rule_digest\n"; }
	return $rule_digest;
}

#subroutine to fetch the latest md5 digest signature file from snort.org
sub md5file
{
	my ($oinkcode,$rule_file,$temp_path,$base_url) = @_;
	my ($getrules_md5,$md5);
	$base_url=slash(0,$base_url);
	print "Checking latest MD5....\n";
    if ($Verbose)
	{ print "\tFetching md5sum for: ".$rule_file.".md5\n"; }
	if ($base_url =~ /snort\.org\/pub/i){
		$getrules_md5 = getstore("http://www.snort.org/pub-bin/oinkmaster.cgi/".$oinkcode."/".$rule_file.".md5",$temp_path.$rule_file.".md5");
    }
	elsif ($base_url =~ /emergingthreats\.net\/rules/i){
		$getrules_md5 = getstore($base_url."/md5sums/".$rule_file.".md5",$temp_path.$rule_file.".md5");
	}
	if ($getrules_md5==403){print "\tA 403 error occured, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n";}
    die "\tError $getrules_md5 when fetching ".$base_url."/".$rule_file.".md5" unless is_success($getrules_md5);
    open (FILE,"$temp_path$rule_file.md5")
          or die $!;
    $md5 = <FILE>;
    chomp ($md5);
	close (FILE);
	$md5 =~ /\w{32}/;  ## Lets just grab the hash out of the string.. don't care about the rest!
	$md5=$&;
	if ($Verbose)
	    { print "\tmost recent rules file digest: $md5\n"; }
    return $md5;
}

# This replaces the copy_rules routine and allows for in-memory processing
# of disablesid, enablesid, dropsid and other sid functions.. here we place
# all of the rules values into a hash as {$gid}{$sid}=$rule
sub read_rules {
	my ($hashref,$path,$extra_rules) = @_;
	my ($file,$sid,$gid,@elements);
	print "\t" if $Verbose;
	print "Reading rules...\n";
	$extra_rules=slash(0,$extra_rules);
	if ( $extra_rules && -f $extra_rules) {
		open (DATA,"$extra_rules") || die "Couldn't read $extra_rules - $!\n";
		my @extra_raw=<DATA>;
		close (DATA);
		my $trk = 0;
		my $record;
		foreach my $row(@extra_raw) {
			$row=trim($row);
			if (($row!~/^#/) && ($row ne "")){ 
				if ($row =~ /\\$/) {
					$row =~ s/\\$//;
					$record=$record . $row;
					$trk=1;
				}
				elsif ($row !~ /\\$/ && $trk == 1) {
					$record=$record . $row;
					if ($record=~/sid:\s*\d+/) {
						$sid=$&;
						$sid=~s/sid:\s*//;
						$$hashref{0}{$sid}=$record;
					}
					$trk=0;
				}else {
					if ($row=~/sid:\s*\d+/) {
						$sid=$&;
						$sid=~s/sid:\s*//;
						$$hashref{0}{$sid}=$row;
					}
					$trk=0;
				}
			}
		} undef @extra_raw;
	}
	if (-d $path) {
		opendir (DIR,"$path");
		while (defined($file = readdir DIR)) {
			open (DATA,"$path$file") || die "Couldn't read $file - $!\n";
			@elements=<DATA>;
			close(DATA);
			
			foreach my $rule(@elements) {
				if ($rule=~/sid:\s*\d+/) {
				$sid=$&;
				$sid=~s/sid:\s*//;
				if ($rule=~/gid:\s*\d/) {
						$gid=$&;
						$gid=~s/gid:\s*//;
				}else{ $gid=1; }
				$$hashref{$gid}{$sid} = $rule;
				}
			}
		} 
		close(DIR);
	}
	elsif (-f $path) {
		open (DATA,"$path") || die "Couldn't read $path - $!";
		@elements=<DATA>;
		close(DATA);
		
		foreach my $rule(@elements) {
			if ($rule=~/sid:\s*\d+/) {
			$sid=$&;
			$sid=~s/sid:\s*//;
			if ($rule=~/gid:\s*\d/) {
					$gid=$&;
					$gid=~s/gid:\s*//;
			}else{ $gid=1; }
			$$hashref{$gid}{$sid} = $rule;
			}
		}
	}
	undef @elements;
}

# sub to generate stub files using the snort --dump-dynamic-rules option
sub gen_stubs
{
    my ($Snort_path,$Snort_config,$Sostubs) = @_;
    unless (-B $Snort_path) { Help ("$Snort_path is not a valid binary file");}
    if (-d $Sostubs && -B $Snort_path && -f $Snort_config) {
        if ($Verbose) { print ("Generating shared object stubs via:$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs\n");}
        system ("$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs");
    } else {
        print ("Something failed in the gen_stubs sub, please verify your shared object config!\n");
        if ($Verbose) {
            unless (-d $Sostubs) { Help ("The path that you specified: $Sostubs does not exist! Please verify your configuration.\n"); }
            unless (-f $Snort_path) { Help ("The file that you specified: $Snort_path does not exist! Please verify your configuration.\n"); }
            unless (-f $Snort_config) { Help ("The file that you specified: $Snort_config does not exist! Please verify your configuration.\n"); }
        }
    }
}  

sub vrt_policy {
	my ($ids_policy,$rule) = @_;
	if ($rule=~/policy\s$ids_policy/i || $rule=~/flowbits:\s?set,/i){
		$rule=~s/^#\s*//;
	}elsif ($rule!~/^#/) {
		$rule="# $rule";
	}
	return $rule;
} 

sub rule_mod {
	my ($ids_policy,$hashref) = @_;
	if ($hashref) {
		if ($ids_policy ne "Disabled") {
			print "Activating $ids_policy rulesets....\n";
			foreach my $k(sort keys %$hashref) {
				for my $k2 (keys %{$hashref->{$k}}) {
					$$hashref{$k}{$k2} = vrt_policy($ids_policy,$$hashref{$k}{$k2});
				}
			}
			print "\tDone\n";
		}
	}	
}

# this relaces the enablesid, disablesid and dropsid functions..
# speed ftw!
sub modifysid {
	my ($function,$SID_conf,$hashref) = @_;
	my (@sid_mod,$sidlist);
	print "Processing $SID_conf....\n";
	if (-f $SID_conf){
		open(DATA, "$SID_conf") or warn "unable to open $SID_conf $!"; 
		while (<DATA>) {
			$sidlist=$_;
			chomp($sidlist);
			$sidlist=trim($sidlist);
			if ( ($sidlist !~ /^\s*#/) && ($sidlist ne "") && !(@sid_mod) ){
				@sid_mod=split(/,/,$sidlist);  #split up the sids that we want to perform the operation on
			} elsif (($sidlist !~ /^\s*#/) && ($sidlist ne "" && @sid_mod)) {
				push(@sid_mod,split(/,/,$sidlist));
			} else {}
		}
		close (DATA);
		if ($hashref) {
			my $sidcount = 0;
			foreach (@sid_mod) {
				if ($_=~/(\d):\d+-\1:\d+/){
					my ($lsid,$usid)=split(/-/,$_);
					my $gid=$lsid;
					$sid_mod[$sidcount]=$lsid;
					$gid=~s/:\d+//;
					$lsid=~s/\d://;
					$usid=~s/\d://;
					while ($lsid<=$usid){
						$lsid++;
						push(@sid_mod,$gid.':'.$lsid);
					} 
				}
				elsif ($_=~/[a-xA-X](\w|\W)*/){
					my $regex = $&;
					$regex =~ s/\|/,/;
					foreach (keys %$hashref) {
						for my $k2 (keys %{$hashref->{$_}}) {
							$sid_mod[$sidcount]=$_.":".$k2 if (($$hashref{$_}{$k2}=~/($regex)/i) && ($sid_mod[$sidcount]=~/[a-xA-X](\w|\W)*/));
							push(@sid_mod,$_.":".$k2) if (($$hashref{$_}{$k2}=~/($regex)/i) && ($sid_mod[$sidcount]=~/\d:\d+/));
						}
					}
				} $sidcount++;
			} $sidcount = 0;
			foreach (@sid_mod) {
				if ($_=~/^1:\d+/ || $_=~/^3:\d+/) {
					my $gid=$&;
					my $sid=$gid;
					if ($gid && $sid) {
						$gid=~s/:\d+//;
						$sid=~s/\d://;
						switch ($function) {
							case "enable" {
								unless (!(defined $$hashref{$gid}{$sid}) || $$hashref{$gid}{$sid}=~/^\s*alert/i || $$hashref{$gid}{$sid}=~/^\s*drop/i) {
									$$hashref{$gid}{$sid}=~s/^\s*#\s*//;
									if ($Verbose) { print "\tEnabled $gid:$sid\n"; }
									$sidcount++;
								}
							}
							case "drop" {
								unless (!(defined $$hashref{$gid}{$sid}) || $$hashref{$gid}{$sid}=~/^\s*drop/i) {
									$$hashref{$gid}{$sid}=~s/^\s*#\s*//;
									$$hashref{$gid}{$sid}=~s/^alert/drop/;
									if ($Verbose) { print "\tWill drop $gid:$sid\n"; }
									$sidcount++;
								}
							}
							case "disable" {
								unless ( !(defined $$hashref{$gid}{$sid}) || $$hashref{$gid}{$sid}=~/^\s*#/) {
									$$hashref{$gid}{$sid}="# ".$$hashref{$gid}{$sid};
									if ($Verbose) { print "\tDisabled $gid:$sid\n"; }
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

sub sig_hup
{
	my ($pidlist) = @_;
	my @pids=split(/,/,$pidlist);
	my $pid;
	print "HangUP Time....\n";
	foreach $pid(@pids) {
		open (FILE,"$pid")
			or die $!;
		my $realpid = <FILE>;
		chomp($realpid);
		close (FILE);
		my $hupres = kill 1, $realpid;
		if ($Verbose) {print "\tSent kill signal to $realpid from $pid with result $hupres\n";}
	}
	if (!$Verbose) {print "\tDone!\n";}	
	undef @pids;
}

sub sid_msg
{
	my ($ruleshash,$sidhash)=@_;
	my ($gid,$arg,$msg);
	print "Generating sid-msg.map....\n";
	foreach my $k (sort keys %$ruleshash) {
		for my $k2 (sort keys %{$ruleshash->{$k}}) {
			(my $header, my $options) = split(/^.* \(/, $$ruleshash{$k}{$k2});
			my @optarray = split(/;(\t|\s)?/,$options) if $options;
			foreach my $option (reverse(@optarray))
			{
                my ($kw, $arg) = split(/:/, $option) if $option;
                if ($kw && $arg) {
	                if ($kw eq "gid")
	                {
	                    $gid = $arg;
	                }
	                elsif ($kw eq "reference")
	                {
	                    push(@{$$sidhash{"$k2"}{"refs"}}, $arg) if $arg;
	                }
	                elsif ($kw eq "msg")
	                {
	                    $arg =~ s/"//g;
	                    $msg = $arg;
	                }
				}
            }
            if ($gid)
            {
                $$sidhash{$k2}{'gid'} = $gid;
            }
            else
            {
                $$sidhash{$k2}{'gid'} = "1";
            }
            $$sidhash{$k2}{'msg'} = $msg unless defined $$sidhash{$k2}{'msg'};
            undef @optarray;
		}
	}
	print "\tDone\n";
}

sub rule_write {
	my ($hashref,$file,$gid)=@_;
	print "Writing $file....\n";
	open(WRITE,">$file") || die "Unable to write $file - $!\n";
	for my $k2 (sort keys %{$hashref->{$gid}}) {
		print WRITE $$hashref{$gid}{$k2};
	}
	close (WRITE);
	print "\tDone\n";
}

sub sid_write
{
	my ($hashref,$file)=@_;
	print "Writing $file....\n";
	open(WRITE,">$file") || die "Unable to write $file -$!";
	foreach my $k (sort keys %$hashref) {
		next unless defined $$hashref{$k}{'msg'};
		print WRITE $k . " || " . $$hashref{$k}{'msg'};
		foreach (@{$$hashref{$k}{'refs'}}) {
			print WRITE " || ".$_;
		}
		print WRITE "\n";
	}
	close(WRITE);
	print "\tDone\n";
}

sub changelog {
	my ($changelog,$hashref,$hashref2,$enabled,$dropped,$disabled,$ips_policy)=@_;
	print "Writing $changelog....\n";
	my (@newsids,@delsids);
	my $rt = 0;
	my $dt = 0;
	foreach my $k1 (sort keys %$hashref) {
		for (sort keys %{$hashref->{$k1}}) {
			push(@newsids,$k1.":".$_) unless exists $$hashref2{$k1}{$_};
			$rt++ unless exists $$hashref2{$k1}{$_};
		}
	}
	foreach my $k1 (sort keys %$hashref2) {
		for (sort keys %{$hashref2->{$k1}}) {
			push(@delsids,$k1.":".$_) unless exists $$hashref{$k1}{$_};
			$dt++ unless exists $$hashref2{$k1}{$_};
		}
	}
	if (-f $changelog) { open(WRITE,">>$changelog") || die "$changelog $!\n"; }
	else { open(WRITE,">$changelog") || die "$changelog $!\n";
		print WRITE "-=BEGIN PULLEDPORK SNORT RULES CHANGELOG, Tracking started on ".gmtime(time)." GMT=-\n\n\n";
	}
	print WRITE "\n-=Begin Changes Logged for ".gmtime(time)." GMT=-\n";
	print WRITE "\nNew Rules\n" if @newsids;
	foreach (@newsids) { print WRITE "\t".$_."\n"; }
	print WRITE "\nDeleted Rules\n" if @delsids;
	foreach (@delsids) { print WRITE "\t".$_."\n"; }
	print WRITE "\nSet Policy: $ips_policy\n" if $ips_policy;
	print WRITE "\nRule Totals\n";
	print WRITE "\tNew:-------$rt\n";
	print WRITE "\tDeleted:---$dt\n";
	print WRITE "\tEnabled:---$enabled\n";
	print WRITE "\tDropped:---$dropped\n";
	print WRITE "\tDisabled:--$disabled\n";
	print WRITE "\tTotal:-----".($enabled+$disabled+$dropped)."\n";
	print WRITE "\n-=End Changes Logged for ".gmtime(time)." GMT=-\n";
	close (WRITE);
	print "\tDone\n";
	undef @newsids;
	undef @delsids;
}

sub trim  #sub to remove whitespace before and after a string
{
	my ($trimmer)=@_;
	if ($trimmer){
		$trimmer=~s/^\s*//;
		$trimmer=~s/\s*$//;
		return $trimmer;
	}
}

sub slash #test for trailing slash and add or remove if needed 1 for add 0 for remove
{
	my ($operation,$string)=@_;
	if ($operation==0 && $string=~/\/$/ && $string ne ""){
		$string=~s/\/$//;
	}elsif ($operation==1 && $string!~/\/$/ && $string ne ""){
		$string=$string."/";
	}
	return $string;	
}


sub Version
{
    print ("$VERSION\n\n");
    exit(0);    
}

## Ok, let's do the magic and actually execute everything in good turn~!

## Lets grab any runtime values and insert into our variables using getopt::long
GetOptions ( "v+" => \$Verbose,
        "V!" => sub { Version() },
		"d!" => \$Hash,
		"l!" => \$Logging,
		"a!" => \$Auto,
        "T!" => \$Textonly,
		"H!" => \$SigHup,
		"n!" => \$NoDownload,
		"h=s" => \$sid_changelog,
		"L=s" => \$local_rules,
        "O=s" => \$oinkcode,
		"s=s" => \$Sorules,
        "t=s" => \$Sostubs,
		"S=s" => \$Snort,
		"a=s" => \$arch,
        "p=s" => \$Snort_path,
		"m=s" => \$sid_msg_map,
		"D=s" => \$Distro,
		"c=s" => \$Config_file,
		"i=s" => \$SID_conf,
		"e=s" => \$enable_conf,
		"I=s" => \$ips_policy,
		"b=s" => \$DISID_conf,
        "C=s" => \$Snort_config,
		"o=s" => \$Output,
        "f=s" => \$rule_file,
		"u=s" => \$base_url,
		"help|?" => sub { Help() });

# Dump our variables for verbose/debug output

if (!$Config_file) {Help("No configuration file specified");}

if ($Verbose) {
    print "Command Line Variable Debug:\n";
    if ($Config_file) {print "\tConfig Path is: $Config_file\n";}
    if ($rule_file) {print "\tRule File is: $rule_file\n";}
	if ($base_url) {print "\tBase URL is: $base_url\n";}
    if ($Output) {print "\tRules file is: $Output\n";}
    if ($local_rules) {print "\tlocal.rules path is: $local_rules\n";}
    if ($Sorules) {print "\tSO Output Path is: $Sorules\n";}
    if ($Sostubs) {print "\tSO Stub File is: $Sostubs\n";}
	if ($sid_msg_map) {print "\tsid-msg.map Output Path is: $sid_msg_map\n";}
	if ($sid_changelog) {print "\tsid changes will be logged to: $sid_changelog\n";}
	if ($ips_policy) {print "\t$ips_policy policy specified\n";}
    if ($Snort) {print "\tSnort Version is: $Snort\n";}
    if ($Snort_path) {print "\tSnort Path is: $Snort_path\n";}
    if ($Snort_config) {print "\tSnort Config File: $Snort_config\n";}
	if ($SID_conf) {print "\tPath to disablesid file: $SID_conf\n";}
	if ($DISID_conf) {print "\tPath to dropsid file: $DISID_conf\n";}
	if ($enable_conf) {print "\tPath to enablesid file: $enable_conf\n";}
    if ($Distro) {print "\tDistro Def is: $Distro\n";}
    if ($arch) {print "\tarch Def is: $arch\n";}
    if ($Verbose) {print "\tVerbose Flag is Set\n";}
    if ($Verbose == 2) {print "\tExtra Verbose Flag is Set\n";}
    if ($Logging) {print "\tLogging Flag is Set\n";}
    if ($Textonly) {print "\tText Rules only Flag is Set\n";}
	if ($SigHup) {print "\tSIGHUP Flag is Set\n";}
	if ($NoDownload) {print "\tNo Download Flag is Set\n";}
    if ($Hash) {print "\tNo MD5 Flag is Set, uhm, ok? I'm gonna fetch the latest file no matter what!\n";}
}

# Call the subroutine to fetch config values
my ($Config_key);
my %Config_info = ();
&parse_config_file ($Config_file, \%Config_info);

if ($Verbose)
{
    print "Config File Variable Debug $Config_file\n";
    foreach $Config_key (keys %Config_info) {
        if ($Config_info{$Config_key}) {print "\t$Config_key = $Config_info{$Config_key}\n";}
    }

}

# Check to see if we have command line inputs, if so, they superseed any config file values!

$pid_path = ($Config_info{'pid_path'}) if exists $Config_info{'pid_path'};
$ignore_files = ($Config_info{'ignore'}) if exists $Config_info{'ignore'};

if (!$base_url) {
	$base_url = ($Config_info{'base_url'});
	if (!$base_url) {Help("You need to specify a base_url to pull the rules files from!");}
}

if (!$Output) {
    $Output = ($Config_info{'rule_path'});
    if (!$Output) {Help("You need to specify an output rules file!");}
}
$Output=slash(0,$Output);

if (!$Sorules) {
    $Sorules = ($Config_info{'sorule_path'});
}
$Sorules=slash(1,$Sorules) if $Sorules;
undef $Sorules if ($Textonly || ($base_url=~/emergingthreats/));

if (!$Sostubs) {
    $Sostubs = ($Config_info{'sostub_path'});
}
$Sostubs=slash(0,$Sostubs) if $Sostubs;
undef $Sostubs if ($Textonly || ($base_url=~/emergingthreats/));

if (!$Distro) {
    $Distro = ($Config_info{'distro'});
}

if (!$arch) {
	$arch = ($Config_info{'arch'});
}

if (!$Snort) {
    $Snort = ($Config_info{'snort'});
}

if (!$Snort_path) {
    $Snort_path =($Config_info{'snort_path'});
}

if (!$local_rules && ($Config_info{'local_rules'})) {
	$local_rules = ($Config_info{'local_rules'});
} elsif (!$local_rules && !($Config_info{'local_rules'})){
	$local_rules=0;
}

if (!$Snort_config) {
    $Snort_config = ($Config_info{'config_path'});
}

if (!$sid_msg_map){
	$sid_msg_map = ($Config_info{'sid_msg'});
}
if (!$sid_changelog){
	$sid_changelog = ($Config_info{'sid_changelog'});
}
# Define the snort rule file that we want
if (!$rule_file) {
    $rule_file = $Config_info{'rule_file'};
    if (!$rule_file) {Help("You need to specify a rules tarball!");}
}

# What is our oinkcode?
if (!$oinkcode) {
    $oinkcode = $Config_info{'oinkcode'};
    if (!$oinkcode) {Help("You need to specify an oinkcode, please get one from snort.org!");}
}
if (!$ips_policy){
	$ips_policy="Disabled";
}
$ips_policy="Disabled" if ($base_url=~/emergingthreats/);

# We need a temp path to work with the files while we do magics on them.. make sure you have plenty 
# of space in this path.. ~200mb is a good starting point
$temp_path = ($Config_info{'temp_path'});
if (!$temp_path) {Help("You need to specify a valid temp path, check permissions too!");}
$temp_path=slash(1,$temp_path);
if (! -d $temp_path) {Help("Temporary file path $temp_path does not exist.\n");}

#let's fetch the most recent md5 file
if ($oinkcode && $rule_file && -d $temp_path)
{
    if (!$NoDownload) {  #only process hup and disablesid changes
		# fetch the latest md5 file
		if (!$Hash) {
			$md5 = md5file($oinkcode,$rule_file,$temp_path,$base_url);
		}
		#and now lets determine the md5 of the last saved rules file if it exists
		if ( -f "$temp_path"."$rule_file" && !$Hash){
			$rule_digest = md5sum($rule_file,$temp_path);
		}
		else { # the file didn't exsist so lets get it
			rulefetch($oinkcode,$rule_file,$temp_path,$base_url);
			if ( -f "$temp_path"."$rule_file" && !$Hash){
				$rule_digest = md5sum($rule_file,$temp_path);
			}
		}

		# compare the online current md5 against against the md5 of the rules file on system
		compare_md5($oinkcode,$rule_file,$temp_path,$Hash,$base_url,$md5,$rule_digest,$Distro,$arch,$Snort,$Sorules,$ignore_files);
    }
	if ($NoDownload) {
		rule_extract($rule_file,$temp_path,$Distro,$arch,$Snort,$Sorules,$ignore_files);
	}
    if ($Output){
		read_rules(\%rules_hash,"$temp_path"."tha_rules/",$local_rules);
    }
    if ($Sorules && $Distro && $Snort && !$Textonly){
		#copy_sorules($temp_path,$Sorules,$Distro,$Snort);
		gen_stubs($Snort_path,$Snort_config,"$temp_path"."tha_rules/so_rules/");
		read_rules(\%rules_hash,"$temp_path"."tha_rules/so_rules/",$local_rules);
    }
} else { Help("Check your oinkcode, temp path and freespace!"); }

if ($temp_path) {
    temp_cleanup();
}

if ($ips_policy ne "Disabled") {
	rule_mod($ips_policy,\%rules_hash);
}

if ($enable_conf && -f $enable_conf) {
	modifysid('enable',$enable_conf,\%rules_hash)
}

if ($DISID_conf && -f $DISID_conf) {
	modifysid('drop',$DISID_conf,\%rules_hash)
}
	
if ($SID_conf && -f $SID_conf) {
	modifysid('disable',$SID_conf,\%rules_hash)
}

if ($sid_changelog && -f $Output) {
	read_rules(\%oldrules_hash,"$Output",$local_rules);
}
if ($sid_changelog && $Sostubs && -f $Sostubs) {
	read_rules(\%oldrules_hash,"$Sostubs",$local_rules);
}

if ($Output) {
	rule_write(\%rules_hash,$Output,1);
}
if ($Sostubs && !$Textonly){
	rule_write(\%rules_hash,$Sostubs,3);
}

if ($sid_msg_map) { 
	
	sid_msg(\%rules_hash,\%sid_msg_map);
	sid_write(\%sid_msg_map,$sid_msg_map);
}

if ($SigHup && $pid_path ne "") {
	sig_hup($pid_path);
}

my $enabled=0;
my $dropped=0;
my $disabled=0;

foreach my $k1 (keys %rules_hash) {
	foreach my $k2 (keys %{$rules_hash{$k1}}) {
		if ($rules_hash{$k1}{$k2}=~/^\s*alert/) {
			$enabled++;
		}
		elsif ($rules_hash{$k1}{$k2}=~/^\s*drop/) {
			$dropped++;
		}
		elsif ($rules_hash{$k1}{$k2}=~/^\s*#/) {
			$disabled++;
		}
	}
}
print "Generating Rule Stats....\n";
print "\tEnabled Rules:----$enabled\n";
print "\tDropped Rules:----$dropped\n";
print "\tDisabled Rules:---$disabled\n";
print "\tTotal Rules:------".($enabled+$dropped+$disabled)."\n\tDone\n";

if ($sid_changelog && -f $Output) {
	changelog($sid_changelog,\%rules_hash,\%oldrules_hash,$enabled,$dropped,$disabled,$ips_policy);
}

print ("Fly Piggy Fly!\n");

__END__
