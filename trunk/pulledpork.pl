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
use Carp;
use Digest::MD5;
use File::Path;
use Getopt::Long qw(:config no_ignore_case bundling);
#use Archive::Tar;  # I dont' need this just yet
use POSIX qw(:errno_h);  

#we are gonna need these!
my ($oinkcode,$temp_path,$rule_file);

my $VERSION = "Pulled_Pork v0.3.6 Dev";

# routine grab our config from the defined config file

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

my ($Verbose,$Logging,$Hash,$ALogger,$i,$Dir,$arg,$Config_file,$Sorules,$Auto,$Output,$opt_help,$Distro,$Snort,$Sostubs,$sid_changelog);
my ($Snort_config,$Snort_path,$Textonly,$Tar_path,$SID_conf,$DISID_conf,$pid_path,$SigHup,$NoDownload,$data,$sid_msg_map,$base_url);
my ($ips_policy,$enable_conf);

$Verbose = 0;
undef($Logging);
undef($Hash);
undef($ALogger);

## Help routine.. display help to stdout then exit
sub Help
{
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
   -o Where do you want me to put generic rules files?
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
   -P Path to your tar binary
   -t Where do you want me to put the so_rule stub files? ** Thus MUST be uniquely 
      different from the -o option value
   -D What Distro are you running on, for the so_rules
      Valid Distro Types=CentOS-4.6,CentOS-5.0,Debian-Lenny,FC-5,FC-9,FreeBSD-7.0,
	  RHEL-5.0,Ubuntu-6.01.1,Ubuntu-8.04
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
my $err = 0;

## Fly piggy fly!
pulledpork();
if($#ARGV==-1){Help();}

# subroutine to cleanup the temp rubbish!!!
sub temp_cleanup
{
    #my $temp_path = @_;
    my $remove = rmtree ( $temp_path."tha_rules" );
    if ($Verbose)
	{ print "removed $remove temporary snort files or directories from $temp_path"."tha_rules!\n"; }
}

# subroutine to extract the files to a temp path so that we can compare the new with the old and report our findings!
sub rule_extract
{	
    my ($oinkcode,$rule_file,$temp_path) = @_;
	print "Prepping files for work....\n";
    if ( -d $temp_path."tha_rules") { 
	if ($Verbose)
	    { print "\toh, we need to perform some cleanup... an unclean run last time?\n"; }
		temp_cleanup($temp_path);
    }
    if ($Verbose)
	{ print "\textracting contents of $temp_path$rule_file to $temp_path"."tha_rules to conduct an excorcism on them!\n"; }
    my $mk_tmp = mkpath($temp_path."tha_rules");
    
    system ( "$Tar_path xfz ".$temp_path.$rule_file." -C ".$temp_path."tha_rules" );
    if ($Verbose)
	{ print "\trules have been extracted, time to move them where they belong!\n"; }
	if (!$Verbose) { print "\tDone!\n"; }
    #rule_move();	
}

# subroutine to actually check the md5 values, if they match we move onto file manipulation routines
sub compare_md5
{
    my ($oinkcode,$rule_file,$temp_path,$Hash,$base_url,$md5,$rule_digest) = @_;
	#print "Checking the MD5....\n";
    if ($rule_digest =~ $md5 && !$Hash){
	if ($Verbose)
	    { print "\tThe MD5 for $rule_file matched $md5 so I'm not gonna download the rules file again suckas!\n"; }
	    if (!$Verbose) { print "\tThey Match\n\tDone!\n"; }
		rule_extract($oinkcode,$rule_file,$temp_path);
	} 
	elsif (!$Hash)
	    {
		if ($Verbose)
		    { print "\tThe MD5 for $rule_file did not match the latest digest... so I am gonna fetch the latest rules file!\n"; }
		if (!$Verbose) { print "\tNo Match\n\tDone\n"; }
			rulefetch($oinkcode,$rule_file,$temp_path,$base_url);
                    $rule_digest = md5sum($rule_file,$temp_path);
                    compare_md5 ($oinkcode,$rule_file,$temp_path,$Hash,$base_url,$md5,$rule_digest);
		} 
	else {
            if ($Verbose)
            { print "\tOk, not verifying the digest.. lame, but that's what you specified!\n";
				print "\tSo if the rules tarball doesn't extract properly and this script dies.. it's your fault!\n";}
			if (!$Verbose) { print "\tNo Verify Set\n\tDone!\n"; }
            rule_extract($oinkcode,$rule_file,$temp_path);
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
    my $local_md5 = open (MD5FILE,"$temp_path$rule_file")
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
	{ print "\tFetching md5sum for comparing from: ".$base_url."/".$rule_file.".md5\n"; }
	if ($base_url =~ /snort\.org\/pub/i){
		$getrules_md5 = getstore("http://www.snort.org/pub-bin/oinkmaster.cgi/".$oinkcode."/".$rule_file.".md5",$temp_path.$rule_file.".md5");
    }
	elsif ($base_url =~ /emergingthreats\.net\/rules/i){
		$getrules_md5 = getstore($base_url."/md5sums/".$rule_file.".md5",$temp_path.$rule_file.".md5");
	}
	if ($getrules_md5==403){print "\tA 403 error occured, please wait for the 15 minute timeout\n\tto expire before trying again or specify the -n runtime switch\n";}
    die "\tError $getrules_md5 when fetching ".$base_url."/".$rule_file.".md5" unless is_success($getrules_md5);
    #print ("storing file at: $path\n");
    my $rule_open = open (FILE,"$temp_path$rule_file.md5")
          or die $!;
    $md5 = <FILE>;
    chomp ($md5);
	close (FILE);
	$md5 =~ m/\w{32}/;  ## Lets just grab the hash out of the string.. don't care about the rest!
	if ($Verbose)
	    { print "\tmost recent rules file digest: $md5\n"; }
    return $md5;
}

## routine to compare files in new ruleset against what we have, outputs the new ones
sub compare_dirs
{
    my ($dir_one,$dir_two) = @_;
    my @unmatched;
    my $unmatcheditem;
    my $item;
    my %seen = ();
    opendir(DIRONE,"$dir_one");
    my @firstDir = readdir DIRONE;
    closedir(DIRONE);
    opendir(DIRTWO,"$dir_two");
    my @secondDir = readdir DIRTWO;
    closedir(DIRTWO);
    
    foreach $item (@secondDir) { $seen{$item} = 1 }
    foreach $item (@firstDir) {
        unless ($seen{$item}) {
            push (@unmatched,$item);
        }
    }
    
    unless (@unmatched eq "") {
        print "New Files:\n";
        foreach $unmatcheditem (@unmatched){
            print $unmatcheditem."\n";
        }
    }
    
}

## routine to output diff results of files themselves
# ultimately this needs to be a little cleaner and have more human readable output?
sub diff_files
{
    my ($file_one,$file_two) = @_;
    if ((-T $file_one) && (-T $file_two) && ($file_one !~ /local\.rules/)) {
		my %diffresults = ();
		
		open (FILEONE,$file_one);
		while (my $line = <FILEONE>) {
			$diffresults{$line}=1;
		}
		
		open (FILETWO,$file_two);
		while (my $line = <FILETWO>) {
			$diffresults{$line}++;
		}
		
		foreach my $line (keys %diffresults) {
			if ($diffresults{$line} == 1) {
				print "Rule change in $file_one\n";
				print "$line\n";
			}
		}
	}
}

# routine to copy rules that we define to copy
# we will also compare the directories and file contents here if verbosity allows for it!
sub copy_rules
{
    my ($temp_path,$Output) = @_;
	print "Copying rules files....\n";
    if ($Verbose) {
        compare_dirs("$temp_path"."tha_rules/rules/",$Output);
    }
    if ( -d "$temp_path"."tha_rules/rules/") {
	opendir (DIR,"$temp_path"."tha_rules/rules/");
	my @files = readdir(DIR);
	closedir(DIR);
    
	foreach my $file (@files) {
            if ($Verbose && !$SID_conf) { diff_files("$temp_path"."tha_rules/rules/$file","$Output$file"); }
	    if ( -f "$temp_path"."tha_rules/rules/$file" && $file !~ "local.rules") {
	        copy("$temp_path"."tha_rules/rules/$file","$Output$file") || print "\tCopy failed with error: $!\n";
	        if ($Verbose == 2) {
	          print ("\tCopied $temp_path"."tha_rules/rules/$file to $Output$file\n");
	        }
	    }
	}
    }
	if (!$Verbose) { print "\tDone!\n"; }
}

sub copy_sorules
{
    #print "$temp_path/tha_rules/so_rules/precompiled/$Distro/i386/$Snort/\n";
    my ($temp_path,$Sorules,$Distro,$Snort) = @_;
	my $arch = "i386";
	if ($Distro =~ "RHEL-5.0" || $Distro =~ "Ubuntu-8.04") { $arch = "x86-64"; } 
	print "Copying Shared Object Rules....\n";
    if ( -d "$temp_path"."tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/") {
	opendir (SODIR,"$temp_path"."tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/");
	my @sofiles = readdir(SODIR);
	closedir(SODIR);
    
	foreach my $sofile (@sofiles) {
	    if ( -f "$temp_path"."tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile") {
	        copy("$temp_path"."tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile","$Sorules$sofile") || print "\tCopy failed with error: $!\n";
	        if ($Verbose == 2) {
	          print ("\tCopying $temp_path"."tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile to $Sorules$sofile\n");
	    } #elsif ($Verbose && ($sofile ne ".") || ($sofile ne "..")) { print ("\tERROR! DOES NOT EXIST:$temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile");}
	        }
	}
    } else { print "\tI couldn't copy the so rules, errors are above.\n"; }
	if (!$Verbose) { print "\tDone!\n"; }
}

# sub to generate stub files using the snort --dump-dynamic-rules option
sub gen_stubs
{
    my ($Snort_path,$Snort_config,$Sostubs) = @_;
    if (-d $Sostubs && -f $Snort_path && -f $Snort_config) {
        if ($Verbose) { print ("Generating shared object stubs via:$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs\n");}
        system ("$Snort_path -c $Snort_config --dump-dynamic-rules=$Sostubs");
    } else {
        print ("Something failed in the gen_stubs sub, please verify your shared object config!\n");
        if ($Verbose) {
            unless (-d $Sostubs) { print ("The path that you specified: $Sostubs does not exist! Please verify your configuration.\n"); }
            unless (-f $Snort_path) { print ("The file that you specified: $Snort_path does not exist! Please verify your configuration.\n"); }
            unless (-f $Snort_config) { print ("The file that you specified: $Snort_config does not exist! Please verify your configuration.\n"); }
        }
    }
}  

sub vrt_policy {
	my ($ids_policy,$rule) = @_;
	if ($rule=~/policy\s$ids_policy/i || $rule=~/flowbits:\s?set,/i){
		$rule=~s/^#\s//;
	}elsif ($rule!~/^#/) {
		$rule="# $rule ## Disabled by PulledPork per VRT metadata for $ids_policy policy";
	}
	return $rule;
} 

sub rule_mod {
	my ($Path,$ids_policy) = @_;
	my (@rulefiles,$file,$rule);
	if (-d $Path) {
		opendir (DIR,"$Path");
		while (defined($file = readdir DIR)) {
			if (-f "$Path$file") {
				open (DATA, "$Path$file") || print "\tWARN, unable to open $Path$file\n";
				my @rulefiles = <DATA>;
				close (DATA);
				foreach $rule(@rulefiles){
					if ($ips_policy ne "Disabled") {
						$rule = trim($rule);
						$rule = vrt_policy($ids_policy,$rule);
						$rule = "$rule\n";
					}
				}
				open(WRITE,">$Path$file" || print "\tWARN, unable to open $Path$file for writing\n");
				print WRITE @rulefiles;
				close(WRITE);
			}
		}
	}
	close(DIR);
		
}

# Here we enable any user specified SIDs
sub enablesid {
	my ($SID_conf,$Output,$Sostubs) = @_;
	my (@sid_enable,$sidlist,$outlist,$solist,$sid_enable,$rule_line,$so_line);
	my $sidcount = 0;
	my $dircount = 0;
	my $sidlines = 0;
	my $txtsid = "";
	my $sosid = "";
	print "Enabling specified SID's....\n";
	if (-f $SID_conf){
		if ($Verbose) { print ("\tProcessing enablesid configuration from $SID_conf\n"); }
		my $SIDDATA = open(DATA, "$SID_conf"); #need to add error foo here
		while (<DATA>) {
			$sidlist=$_;
			chomp($sidlist);
			$sidlist=trim($sidlist);
			if ( ($sidlist !~ /^#/) && ($sidlist ne "") && ($sidcount < 1) ){
				@sid_enable=split(/,/,$sidlist);  #split up the sids that we want to disable
				$sidcount++
			} elsif (($sidlist !~ /^#/) && ($sidlist ne "")) {
				push(@sid_enable,split(/,/,$sidlist));
			} else {}
		}
		close (DATA);
		if (-d $Sostubs) {
			opendir(DIR,"$Sostubs"); ## Open the stubs directory
			while (defined($solist=readdir DIR)){
				open(DATA,"$Sostubs$solist");  #Open the shared object stubs
				my @so_lines = <DATA>;
				close(DATA);
				$sidcount = 0;
				foreach $so_line(@so_lines) {
					$so_line=trim($so_line);
					if ( ($so_line !~ /^alert/i) && ($so_line !~ /^drop/i) && ($so_line ne"") ){  #don't want already enabled lines or blank ones!
						foreach $sid_enable(@sid_enable) {
							if ($sid_enable=~/^3:/) {
								$sosid=$sid_enable;
								$sosid=~s/^3://;
								if (($sosid ne "") && ($so_line=~/sid:$sosid;/i)) {
									$sidcount++;
									$so_line=~s/^# //;
									$so_line =~ s/\s##\s.+//;
									chomp($so_line);
									$so_line = "$so_line\n## ENABLED Shared Object SID:$sosid BY PULLEDPORK per directive in $SID_conf";
									if ($Verbose) { print "\tENABLED in $Sostubs$solist -> $so_line\n"; }
								}
							}
						}
					}
					$so_line = "$so_line\n";
				}
				if ($sidcount > 0) {
					open(WRITE,">$Sostubs$solist");
					print WRITE @so_lines;
					close(WRITE);
					if (!$Verbose) { print "\tEnabled $sidcount rules in $Sostubs$solist\n"; }
				}
			}
		}
		close(DIR);
		opendir(DIR,"$Output"); #need to add error foo here
		while (defined($outlist=readdir DIR)){
			open(DATA,"$Output$outlist");  #open the file that we are gonna sed to disable the sid, this is GID1's only
			my @rule_lines = <DATA>;
			close (DATA);
			$dircount = 0;
			foreach $rule_line(@rule_lines) {	
				$rule_line=trim($rule_line);
				if ( ($rule_line !~ /^alert/i) && ($rule_line !~ /^drop/i) && ($rule_line ne"") ){  #don't want already enabled rules or blank ones!
					foreach $sid_enable(@sid_enable) {
						#print "\t$sid_enable\n";
						if ($sid_enable=~/^1:/) { 
							$txtsid=$sid_enable;
							$txtsid=~s/^1://;
						#print "\tsid:$txtsid;\n";
							if (($txtsid ne "") && ($rule_line=~/sid:$txtsid;/i)) {
								#$sidcount++;
								$dircount++;
								$rule_line =~ s/^# //;
								$rule_line =~ s/\s##\s.+//;
								chomp($rule_line);
								$rule_line =  "$rule_line\n## ENABLED sid:$txtsidBY PULLEDPORK per directive in $SID_conf";
								if ($Verbose) { print "\tEnabled in $Output$outlist -> $rule_line\n"; }
							}
						}
					}
				}
				$rule_line = "$rule_line\n";
			}
			if ($dircount > 0) {
				open(WRITE,">$Output$outlist");
				print WRITE @rule_lines;
				close (WRITE);
				if (!$Verbose) { print "\tEnabled $dircount rules in $Output$outlist\n"; }
			}
		}
		close (DIR);
	}
	print "\tDone\n";	
}

sub disablesid  #routine to disable the user specified SIDS, we are also accounting for policy manipulation here
{
	my ($SID_conf,$Output,$Sostubs) = @_;
	my (@sid_disable,$sidlist,$outlist,$solist,$sid_disable,$rule_line,$so_line);
	my $sidcount = 0;
	my $dircount = 0;
	my $sidlines = 0;
	my $txtsid = "";
	my $sosid = "";
	print "Disabling specified SID's....\n";
	if (-f $SID_conf){
		if ($Verbose) { print ("\tProcessing disablesid configuration from $SID_conf\n"); }
		my $SIDDATA = open(DATA, "$SID_conf"); #need to add error foo here
		while (<DATA>) {
			$sidlist=$_;
			chomp($sidlist);
			$sidlist=trim($sidlist);
			if ( ($sidlist !~ /^#/) && ($sidlist ne "") && ($sidcount < 1) ){
				@sid_disable=split(/,/,$sidlist);  #split up the sids that we want to disable
				$sidcount++
			} elsif (($sidlist !~ /^#/) && ($sidlist ne "")) {
				push(@sid_disable,split(/,/,$sidlist));
			} else {}
		}
		close (DATA);
		if (-d $Sostubs) {
			opendir(DIR,"$Sostubs"); ## Open the stubs directory
			while (defined($solist=readdir DIR)){
				open(DATA,"$Sostubs$solist");  #Open the shared object stubs
				my @so_lines = <DATA>;
				close(DATA);
				$sidcount = 0;
				foreach $so_line(@so_lines) {
					$so_line=trim($so_line);
					if ( ($so_line !~ /^#/) && ($so_line ne"") ){  #don't want already disabled lines or blank ones!
						foreach $sid_disable(@sid_disable) {
							if ($sid_disable=~/^3:/) {
								$sosid=$sid_disable;
								$sosid=~s/^3://;
								if (($sosid ne "") && ($so_line=~/sid:$sosid;/i)) {
									$sidcount++;
									$so_line = "# $so_line ## DISABLED Shared Object BY PULLEDPORK per directive in $SID_conf";
									if ($Verbose) { print "\tDisabled in $Sostubs$solist -> $so_line\n"; }
								}
							}
						}
					}
					$so_line = "$so_line\n";
				}
				if ($sidcount > 0) {
					open(WRITE,">$Sostubs$solist");
					print WRITE @so_lines;
					close(WRITE);
					if (!$Verbose) { print "\tDisabled $sidcount rules in $Sostubs$solist\n"; }
				}
			}
		}
		close(DIR);
		opendir(DIR,"$Output"); #need to add error foo here
		while (defined($outlist=readdir DIR)){
			open(DATA,"$Output$outlist");  #open the file that we are gonna sed to disable the sid, this is GID1's only
			my @rule_lines = <DATA>;
			close (DATA);
			$dircount = 0;
			foreach $rule_line(@rule_lines) {	
				$rule_line=trim($rule_line);
				if ( ($rule_line !~ /^#/) && ($rule_line ne"") ){  #don't want already disabled lines or blank ones!
					foreach $sid_disable(@sid_disable) {
						#print "\t$sid_disable\n";
						if ($sid_disable=~/^1:/) { 
							$txtsid=$sid_disable;
							$txtsid=~s/^1://;
						#print "\tsid:$txtsid;\n";
							if (($txtsid ne "") && ($rule_line=~/sid:$txtsid;/i)) {
								#$sidcount++;
								$dircount++;
								$rule_line =  "# $rule_line ## DISABLED BY PULLEDPORK per directive in $SID_conf";
								if ($Verbose) { print "\tDisabled in $Output$outlist -> $rule_line\n"; }
							}
						}
					}
				}
				$rule_line = "$rule_line\n";
			}
			if ($dircount > 0) {
				open(WRITE,">$Output$outlist");
				print WRITE @rule_lines;
				close (WRITE);
				if (!$Verbose) { print "\tDisabled $dircount rules in $Output$outlist\n"; }
			}
		}
		close (DIR);
	}
	print "\tDone\n";
}

sub dropsid  #routine to set certain SIDS to drop
{
	my ($DISID_conf,$Output,$Sostubs) = @_;
	my (@sid_drop,$sidlist,$outlist,$solist,$sid_drop,$rule_line,$so_line);
	my $sidcount = 0;
	my $dircount = 0;
	my $sidlines = 0;
	my $txtsid = "";
	my $sosid = "";
	print "Setting your chosen SIDs to Drop....\n";
	if (-f $DISID_conf){
		if ($Verbose) { print ("\tProcessing dropsid configuration from $DISID_conf\n"); }
		my $SIDDATA = open(DATA, "$DISID_conf"); #need to add error foo here
		while (<DATA>) {
			$sidlist=$_;
			chomp($sidlist);
			$sidlist=trim($sidlist);
			if ( ($sidlist !~ /^#/) && ($sidlist ne "") && ($sidcount < 1) ){
				@sid_drop=split(/,/,$sidlist);  #split up the sids that we want to drop
				$sidcount++
			} elsif (($sidlist !~ /^#/) && ($sidlist ne "")) {
				push(@sid_drop,split(/,/,$sidlist));
			} else {}
		}
		close (DATA);
		if (-d $Sostubs) {
			opendir(DIR,"$Sostubs"); ## Open the stubs directory
			while (defined($solist=readdir DIR)){
				open(DATA,"$Sostubs$solist");  #Open the shared object stubs
				my @so_lines = <DATA>;
				close(DATA);
				$sidcount = 0;
				foreach $so_line(@so_lines) {
					$so_line=trim($so_line);
					if ( ($so_line !~ /^#/) && ($so_line ne"") ){  #don't want disabled lines or blank ones!
						foreach $sid_drop(@sid_drop) {
							if ($sid_drop=~/^3:/) {
								$sosid=$sid_drop;
								$sosid=~s/^3://;
								if (($sosid ne "") && ($so_line=~/sid:$sosid;/i)) {
									$sidcount++;
									$so_line=~s/^alert/drop/i;
									$so_line = "$so_line ## DROPPED by pulledpork per directive in $DISID_conf";
									if ($Verbose) { print "\tDropped in $Sostubs$solist -> $so_line\n"; }
								}
							}
						}
						$so_line = "$so_line\n";
					}
				}
				if ($sidcount > 0) {
					open(WRITE,">$Sostubs$solist");
					print WRITE @so_lines;
					close(WRITE);
					if (!$Verbose) { print "\tSet $sidcount rules to Drop in $Sostubs$solist\n"; }
				}
			}
		}
		close(DIR);
		opendir(DIR,"$Output"); #need to add error foo here
		while (defined($outlist=readdir DIR)){
			open(DATA,"$Output$outlist");  #open the file that we are gonna sed to drop the sid, this is GID1's only
			my @rule_lines = <DATA>;
			close (DATA);
			$dircount = 0;
			foreach $rule_line(@rule_lines) {	
				$rule_line=trim($rule_line);
				if ( ($rule_line !~ /^#/) && ($rule_line ne"") ){  #don't want disabled lines or blank ones!
					foreach $sid_drop(@sid_drop) {
						#print "\t$sid_drop\n";
						if ($sid_drop=~/^1:/) { 
							$txtsid=$sid_drop;
							$txtsid=~s/^1://;
						#print "\tsid:$txtsid;\n";
							if (($txtsid ne "") && ($rule_line=~/sid:$txtsid;/i)) {
								#$sidcount++;
								$dircount++;
								$rule_line=~s/^alert/drop/i;
								$rule_line =  "$rule_line ## DROPPED BY PULLEDPORK per directive in $DISID_conf";
								if ($Verbose) { print "\tDropped in $Output$outlist -> $rule_line\n"; }
							}
						}
					}
				$rule_line = "$rule_line\n";
				}
			}
			if ($dircount > 0) {
				open(WRITE,">$Output$outlist");
				print WRITE @rule_lines;
				close (WRITE);
				if (!$Verbose) { print "\tSet $dircount rules to Drop in $Output$outlist\n"; }
			}
		}
		close (DIR);
	}
	print "\tDone\n";
}

sub sig_hup
{
	my ($pidlist) = @_;
	my @pids=split(/,/,$pidlist);
	my $pid;
	print "HangUP Time....\n";
	foreach $pid(@pids) {
		my $pid_open = open (FILE,"$pid")
			or die $!;
		my $realpid = <FILE>;
		chomp($realpid);
		close (FILE);
		my $hupres = kill 1, $realpid;
		if ($Verbose) {print "\tSent kill signal to $realpid from $pid with result $hupres\n";}
	}
	if (!$Verbose) {print "\tDone!\n";}
	
}

sub sid_msg
{
    my ($dir)=@_;
    my ($list,$sid,$msg,$ref,$sidline,@sids);
	if (-d $dir){
		opendir (DIR,"$dir");
		while (defined($list=readdir DIR)){
			open (DATA,"$dir$list");
			my @sid_multi = <DATA>;
			close (DATA);
			my (@sid_lines,$data_ins,$trk);
			$trk=0;
			## Here we handle multiline rules, even though there are none in any official rule releases!
			#my @sid_multi = @sid_lines;
			foreach $data(@sid_multi) {
				$data=trim($data);
				if (($data!~/^#/) && ($data ne "")){ 
					if ($data =~ /\\$/) {
						$data =~ s/\\$//;
						$data_ins=$data_ins . $data;
						$trk=1;
					}
					elsif ($data !~ /\\$/ && $trk == 1) {
						$data_ins=$data_ins . $data;
						push(@sid_lines,$data_ins);
						$trk=0;
					}else {
						push(@sid_lines,$data);
						$trk=0;
					}
				}
			}
			foreach $data(@sid_lines){
				$data=trim($data);
				if (($data!~/^#/) && ($data ne "")){ #We don't want blanklines or commented lines
					
					$sid=$data;
					$msg=$data;
					$ref=$data;
					#get the sid of the rule
					if ($sid=~/sid:\s?\d+;/i) {
						$sid=$&;
						$sid=~s/(sid:|;)//ig;
						$sid=trim($sid);
						$sidline="$sid || ";
					}
					# get the msg of the rule
					if ($msg=~/msg:\s?"(\w| |\-|\.|\+|\/|\$|\%|\^|\&|\*|\!|\[|\]|\~|\>|\<|\/|,|\#|\?|\$|\@|\=|\'|\(|\))+";/i) {
						$msg=$&;
						$msg=~s/(msg:"|";)//ig;
						$msg=trim($msg);
						$sidline="$sidline$msg";
					}
					# get the reference(s) out of the rule (everything but arachnids anyway)
					if ($ref=~/reference:\s?(\/|\w|\.|,|:|\-|\$|\@|\?|\=|\|\%')+;/i) {
						my @refs = split (/;/,$ref);
						foreach $ref(@refs){
							#$ref=$&;
							if (($ref=~/reference:\s?(\/|\w|\.|,|:|\-|\$|\@|\?|\=|\|\%')+/i) && ($ref!~/arachnids/i)) {
								$ref=~s/reference://ig;
								$ref=trim($ref);
								$sidline="$sidline || $ref";
							}
						} $sidline="$sidline";
					} #else { $sidline="$sidline";}
					$sidline=trim($sidline);
					if ($sidline && $sidline !~ /^\s+/g){
						push (@sids,$sidline); #stick it all into an array so we can dedupe later
					}
				}
			}
		}
		close (DIR);
		@sids = do { my %h; @h{@sids} = @sids; values %h }; #dedupe the shiz
		@sids=sort(@sids);
		foreach $sidline(@sids){
			$sidline="$sidline\n";
		}
		return @sids;
	}
}

sub sid_diff {
	my ($sidone,$sidtwo)=@_;
	my %sidkey = map {$_,1} @{$sidone};
	my @siddiff = grep {!$sidkey {$_}} @{$sidtwo};
	return @siddiff;	
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
        "O=s" => \$oinkcode,
		"s=s" => \$Sorules,
        "t=s" => \$Sostubs,
		"S=s" => \$Snort,
        "p=s" => \$Snort_path,
		"m=s" => \$sid_msg_map,
        "P=s" => \$Tar_path,
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

if (!$Config_file) {Help();}

if ($Verbose) {
    print "Command Line Variable Debug:\n";
    if ($Config_file) {print "\tConfig Path is: $Config_file\n";}
    if ($rule_file) {print "\tRule File is: $rule_file\n";}
	if ($base_url) {print "\tBase URL is: $base_url\n";}
    if ($Output) {print "\tOutput Path is: $Output\n";}
    if ($Sorules) {print "\tSO Output Path is: $Sorules\n";}
    if ($Sostubs) {print "\tSO Stub Output Path is: $Sostubs\n";}
	if ($sid_msg_map) {print "\tsid-msg.map Output Path is: $sid_msg_map\n";}
	if ($sid_changelog) {print "\tsid changes will be logged to: $sid_changelog\n";}
	if ($ips_policy) {print "\t$ips_policy policy specified\n";}
    if ($Snort) {print "\tSnort Version is: $Snort\n";}
    if ($Snort_path) {print "\tSnort Path is: $Snort_path\n";}
    if ($Tar_path) {print "\tTar Path is: $Tar_path\n";}
    if ($Snort_config) {print "\tSnort Config File: $Snort_config\n";}
	if ($SID_conf) {print "\tPath to disablesid file: $SID_conf\n";}
	if ($DISID_conf) {print "\tPath to dropsid file: $DISID_conf\n";}
    if ($Distro) {print "\tDistro Def is: $Distro\n";}
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

$pid_path = ($Config_info{'pid_path'});

if (!$base_url) {
	$base_url = ($Config_info{'base_url'});
	if (!$base_url) {Help();}
}

if (!$Output) {
    $Output = ($Config_info{'rule_path'});
    if (!$Output) {Help();}
}
$Output=slash(1,$Output);

if (!$Sorules) {
    $Sorules = ($Config_info{'sorule_path'});
}
$Sorules=slash(1,$Sorules);

if (!$Sostubs) {
    $Sostubs = ($Config_info{'sostub_path'});
}
$Sostubs=slash(1,$Sostubs);

if (!$Distro) {
    $Distro = ($Config_info{'distro'});
}
if (!$Snort) {
    $Snort = ($Config_info{'snort'});
}
if (!$Snort_path) {
    $Snort_path =($Config_info{'snort_path'});
}
if (!$Snort_config) {
    $Snort_config = ($Config_info{'config_path'});
}
if (!$Tar_path) {
    $Tar_path = ($Config_info{'tar_path'});
    if (!$Tar_path) {Help();}
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
    if (!$rule_file) {Help();}
}

# What is our oinkcode?
if (!$oinkcode) {
    $oinkcode = $Config_info{'oinkcode'};
    if (!$oinkcode) {Help();}
}
if (!$ips_policy){
	$ips_policy="Disabled";
}

# We need a temp path to work with the files while we do magics on them.. make sure you have plenty 
# of space in this path.. ~200mb is a good starting point
$temp_path = ($Config_info{'temp_path'});
if (!$temp_path) {Help();}
$temp_path=slash(1,$temp_path);
if (! -d $temp_path) { print "$0: Temporary file path $temp_path does not exist.\n";
	exit(1);
}

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
		compare_md5($oinkcode,$rule_file,$temp_path,$Hash,$base_url,$md5,$rule_digest);
    }
	if ($NoDownload) {
		rule_extract($oinkcode,$rule_file,$temp_path);
	}
    if ($Output){
		copy_rules($temp_path,$Output);
    }
    if ($Sorules && $Distro && $Snort && !$Textonly){
		copy_sorules($temp_path,$Sorules,$Distro,$Snort);
		gen_stubs($Snort_path,$Snort_config,$Sostubs);
    }
} else { Help(); }

if ($temp_path) {
    temp_cleanup();
}

if ($Output && $ips_policy ne "Disabled") {
	rule_mod($Output,$ips_policy);
	if (-d $Sostubs) {
		rule_mod($Sostubs, $ips_policy);
	}
}
	
if ($SID_conf && -d $Output) {
	disablesid($SID_conf,$Output,$Sostubs)
}

if ($DISID_conf && -d $Output) {
	dropsid($DISID_conf,$Output,$Sostubs)
}

if ($enable_conf && -d $Output) {
	enablesid($enable_conf,$Output,$Sostubs)
}

if ($sid_msg_map && -d $Output) { 
	print "Generating sid-msg.map...\n";
	my @sidlist=sid_msg($Output);
	if (-d $Sostubs && !$Textonly) {
		push (@sidlist,sid_msg($Sostubs));
	}
	if (-f $sid_msg_map && $sid_changelog) {
		print "\tGenerating SID changelog at $sid_changelog\n";
		my $time = gmtime(time);
		open(READ,"$sid_msg_map");
		my @oldsids=<READ>;
		close(READ);
		my @sidchange=sid_diff(\@oldsids,\@sidlist);
		if ($Verbose) {
			foreach $data(@sidchange){
				print "\tSID CHANGE $data\n";
			}
		}
		my $newsid=0;
		if (-f $sid_changelog) {open(WRITE,">>$sid_changelog");}
		else {
			open(WRITE,">$sid_changelog");
			print WRITE "-=BEGIN PULLEDPORK SID CHANGELOG, Tracking started on $time GMT=-\n\n\n";
			$newsid=1;
		}
		if ($newsid==0) {
			print WRITE "\n-=Begin Changes Logged for $time GMT=-\n";
			print WRITE @sidchange;
			print WRITE "\n-=End Changes Logged for $time GMT=-\n";
		}
		close(WRITE);
	}
	open(WRITE,">$sid_msg_map");
	print WRITE @sidlist;
	close(WRITE);
	print "\tDone\n";
}
if ($SigHup && $pid_path ne "") {
	sig_hup($pid_path);
}
print ("Fly Piggy Fly!\n");

__END__
