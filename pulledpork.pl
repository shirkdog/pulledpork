#!/usr/bin/perl

## pulledpork v0.1 Beta1
## cummingsj@gmail.com

# Copyright (C) 2009 JJ Cummings

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
use Archive::Tar;
use POSIX qw(:errno_h)  ## For Addind signal handling

#we are gonna need these!
my ($oinkcode,$temp_path,$rule_file);

my $VERSION = "Pulled_Pork v0.2.1";

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
        chop ($config_line);          # Get rid of the trailling \n
        $config_line =~ s/^\s*//;     # Remove spaces at the start of the line
        $config_line =~ s/\s*$//;     # Remove spaces at the end of the line
        if ( ($config_line !~ /^#/) && ($config_line ne "") ){    # Ignore lines starting with # and blank lines
            ($Name, $Value) = split (/=/, $config_line);          # Split each line into name value pairs
            $$Config_val{$Name} = $Value;                             # Create a hash of the name value pairs
        }
    }

    close(CONFIG);

}

my ($Verbose,$Logging,$Hash,$ALogger,$Me,$i,$Dir,$arg,$Config_file,$Sorules,$Auto,$Output,$opt_help,$Distro,$Snort,$Sostubs);
my ($Snort_config,$Snort_path,$Textonly,$Tar_path,$SID_conf);
$Verbose = 0;
undef($Logging);
undef($Hash);
undef($ALogger);
($Me)=split("/", reverse($0));
($Me)=split(" ", reverse($Me));

## Help routine.. display help to stdout then exit
sub Help
{
    open(ME, "<$0");
    for ($i=0; $i<38; $i++) { $_=<ME>; }
    close(ME);

    #$_ = substr($_, 16, 20);
    printf("Usage:\t%s [-lvvVdaT? -help] -c <config filename> -o <rule output path> \t/\n", $Me);
    printf("\t-O <oinkcode> -s <so_rule output directory> -D <Distro> -S <SnortVer> \t/\n");
    printf("\t-p <path to your snort binary> -C <path to your snort.conf> -t <sostub output path>\n");
    printf("\n\tUsed to fetch and validate latest Snort rules from snort.org.\n\n");
    #printf("\tVersion: 0.1 Beta 1\n\n");
    printf("\tOptions:\n");
    printf("\t-c\tWhere the pulledpork config file lives.\n");
	printf("\t-i\tWhere the disablesid config file lives.\n");
    printf("\t-o\tWhere do you want me to put generic rules files?\n");
    printf("\t-O\tWhat is your Oinkcode?\n");
    printf("\t-T\tProcess text based rules files only, i.e. DO NOT process so_rules\n");
    printf("\t-s\tWhere do you want me to put the so_rules?\n");
    printf("\t-S\tSpecify your Snort version\n");
    printf("\t\tValid options for this value 2.8.0.1,2.8.0.2,2.8.1,2.8.2,2.8.2.1,2.8.2.2,2.8.3,2.8.3.1,2.8.3.2,2.8.4\n");
    printf("\t-C\tPath to your snort.conf\n");
    printf("\t-p\tPath to your Snort binary\n");
    printf("\t-P\tPath to your tar binary\n");
    printf("\t-t\tWhere do you want me to put the so_rule stub files? ** Thus MUST be uniquely different from the -o option value\n");
    printf("\t-D\tWhat Distro are you running on, for the so_rules\n");
    printf("\t\tValid Distro Types=CentOS-4.6,CentOS-5.0,Debian-Lenny,FC-5,FC-9,FreeBSD-7.0,RHEL-5.0,Ubuntu-6.01.1,Ubuntu-8.04\n");
    printf("\t-l\tLog information to logger rather than stdout messages.  **not yet implemented**\n");
    printf("\t-v\tVerbose mode, you know.. for troubleshooting and such nonsense.\n");
    printf("\t-vv\tEXTRA Verbose mode, you know.. for in-depth troubleshooting and other such nonsense.\n");
    printf("\t-d\tDo not verify signature of rules tarball, why though?.\n");
    printf("\t-a\tRun in auto mode (all options will be specified in the config file, not at runtime)\n");
    printf("\t-V\tPrint Version and exit\n");
    printf("\t-help/?\tPrint this help info.\n\n");
    exit(0);
}

## OMG We MUST HAVE FLYING PIGS!
sub pulledpork
{
    system("clear");
    #printf("\n\npulledpork!!! I Can Haz Snort Rules to Fly With?\n");
    printf("http://code.google.com/p/pulledpork/\n\n");
    printf("\t     _____ ____\n");
    printf("\t    `----,\\    )\n");
    printf("\t     `--==\\\\  /\t\t$VERSION\n");
    printf("\t      `--==\\\\/\n");
    printf("\t    .-~~~~-.Y|\\\\_\tCopyright (C) 2009 JJ Cummings\n");
    printf("\t \@_/        /  66\\_\tcummingsj\@gmail.com\n");
    printf("\t   |    \\   \\   _(\")\n");
    printf("\t    \\   /-| ||'--'\tRules give me wings!\n");
    printf("\t     \\_\\  \\_\\\\\n\n");
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
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
    my $remove = rmtree ( $temp_path."/tha_rules" );
    if ($Verbose)
	{ print "removed $remove temporary snort files or directories from $temp_path/tha_rules!\n"; }
}

# subroutine to extract the files to a temp path so that we can compare the new with the old and report our findings!
sub rule_extract
{	
    my ($oinkcode,$rule_file,$temp_path) = @_;
	print "Prepping files for work....\n";
    if ( -d $temp_path."/tha_rules") { 
	if ($Verbose)
	    { print "\toh, we need to perform some cleanup... an unclean run last time?\n"; }
		temp_cleanup($temp_path);
    }
    if ($Verbose)
	{ print "\textracting contents of $temp_path/$rule_file to $temp_path/tha_rules to conduct an excercism on them!\n"; }
    my $mk_tmp = mkpath("$temp_path/tha_rules");
    
    system ( "$Tar_path xfz ".$temp_path."/".$rule_file." -C ".$temp_path."/tha_rules" );
    if ($Verbose)
	{ print "\trules have been extracted, time to move them where they belong!\n"; }
	if (!$Verbose) { print "\tDone!\n"; }
    #rule_move();	
}

# subroutine to actually check the md5 values, if they match we move onto file manipulation routines
sub compare_md5
{
    my ($oinkcode,$rule_file,$temp_path,$Hash) = @_;
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
			rulefetch($oinkcode,$rule_file,$temp_path);
                    md5sum($rule_file,$temp_path);
                    compare_md5 ($oinkcode,$rule_file,$temp_path,$Hash);
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
    my ($oinkcode,$rule_file,$temp_path) = @_;
    print "Rules tarball download....\n";
	if ($Verbose)
	{ print "\tFetching rules file: $rule_file\n";
        if ($Hash) { print "But not verifying MD5\n"; }
         }
    my $getrules_rule = getstore("http://www.snort.org/pub-bin/oinkmaster.cgi/".$oinkcode."/".$rule_file,$temp_path."/".$rule_file);
    die "\tError $getrules_rule when fetching http://www.snort.org/pub-bin/oinkmaster.cgi/<OINKCODE>/".$rule_file unless is_success($getrules_rule);
    if ($Verbose)
	{ print ("\tstoring file at: $temp_path/$rule_file\n\n"); }
	if (!$Verbose) { "\tDone!\n"; }
}

#subroutine to deterine the md5 digest of the current rules file
sub md5sum
{
    my ($rule_file,$temp_path) = @_;
    my $local_md5 = open (MD5FILE,"$temp_path/$rule_file")
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
}

#subroutine to fetch the latest md5 digest signature file from snort.org
sub md5file
{
	my ($oinkcode,$rule_file,$temp_path) = @_;
	print "Checking latest MD5....\n";
    if ($Verbose)
	{ print "\tFetching md5sum for comparing from: http://www.snort.org/pub-bin/oinkmaster.cgi/<OINKCODE>/".$rule_file.".md5\n"; }
    my $getrules_md5 = getstore("http://www.snort.org/pub-bin/oinkmaster.cgi/".$oinkcode."/".$rule_file.".md5",$temp_path."/".$rule_file.".md5");
    die "\tError $getrules_md5 when fetching http://www.snort.org/pub-bin/oinkmaster.cgi/<OINKCODE>/".$rule_file.".md5" unless is_success($getrules_md5);
    #print ("storing file at: $path\n");
    my $rule_open = open (FILE,"$temp_path/$rule_file.md5")
          or die $!;
    $md5 = <FILE>;
    chomp ($md5);
	$md5 =~ /[0-9a-bA-B]{32}/;  ## Lets just grab the hash out of the string.. don't care about the rest!
    if ($Verbose)
	    { print "\tmost recent rules file digest: $md5\n"; }
    close (FILE);
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
    #my $length1 = @firstDir;
    #my $length2 = @secondDir;
    
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

# routine to copy rules that we define to copy
# we will also compare the directories and file contents here if verbosity allows for it!
sub copy_rules
{
    my ($temp_path,$Output) = @_;
	print "Copying rules files....\n";
    if ($Verbose) {
        compare_dirs("$temp_path/tha_rules/rules/",$Output);
    }
    if ( -d "$temp_path/tha_rules/rules/") {
	opendir (DIR,"$temp_path/tha_rules/rules/");
	my @files = readdir(DIR);
	closedir(DIR);
    
	foreach my $file (@files) {
            if ($Verbose && !$SID_conf) { diff_files("$temp_path/tha_rules/rules/$file","$Output$file"); }
	    if ( -f "$temp_path/tha_rules/rules/$file") {
	        copy("$temp_path/tha_rules/rules/$file","$Output$file") || print "\tCopy failed with error: $!\n";
	        if ($Verbose == 2) {
	          print ("\tCopied $temp_path/tha_rules/rules/$file to $Output$file\n");
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
    if ( -d "$temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/") {
	opendir (SODIR,"$temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/");
	my @sofiles = readdir(SODIR);
	closedir(SODIR);
    
	foreach my $sofile (@sofiles) {
	    if ( -f "$temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile") {
	        copy("$temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile","$Sorules$sofile") || print "\tCopy failed with error: $!\n";
	        if ($Verbose == 2) {
	          print ("\tCopying $temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile to $Sorules$sofile\n");
	        }
	    } else { print ("\tERROR! DOES NOT EXIST:$temp_path/tha_rules/so_rules/precompiled/$Distro/$arch/$Snort/$sofile");
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

sub disablesid  #routine to disable the sids.. this is a rough approximation of what it will be, still needs some work, multilin handling etc
{
	my ($SID_conf,$Output,$Sostubs) = @_;
	my (@sid_disable,$sidlist,$outlist,$solist,$sid_disable,$rule_line,$so_line);
	my $sidcount = 0;
	my $dircount = 0;
	my $sidlines = 0;
	my $txtsid = "";
	my $sosid = "";
	print "Disabling your chosen SID's....\n";
	if (-f $SID_conf){
		if ($Verbose) { print ("\tProcessing disablesid configuration from $SID_conf\n"); }
		my $SIDDATA = open(DATA, "$SID_conf"); #need to add error foo here
		while (<DATA>) {
			$sidlist=$_;
			chop($sidlist);
			$sidlist =~ s/^\s*//;     # Remove spaces at the start of the line
			$sidlist =~ s/\s*$//;     # Remove spaces at the end of the line
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
					$so_line=~s/^\s*//;
					$so_line=~s/\s*$//;
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
						$so_line = "$so_line\n";
					}
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
				$rule_line=~s/^\s*//;
				$rule_line=~s/\s*$//;
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
				$rule_line = "$rule_line\n";
				}
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
		#"h!" => sub { Help() },
        "O=s" => \$oinkcode,
		"s=s" => \$Sorules,
        "t=s" => \$Sostubs,
		"S=s" => \$Snort,
        "p=s" => \$Snort_path,
        "P=s" => \$Tar_path,
		"D=s" => \$Distro,
		"c=s" => \$Config_file,
		"i=s" => \$SID_conf,
        "C=s" => \$Snort_config,
		"o=s" => \$Output,
        "f=s" => \$rule_file,
		"help|?" => sub { Help() });

# Dump our variables for verbose/debug output

if (!$Config_file) {Help();}

if ($Verbose) {
    print "Command Line Variable Debug:\n";
    if ($Config_file) {print "\tConfig Path is: $Config_file\n";}
    if ($rule_file) {print "\tRule File is: $rule_file\n";}
    if ($Output) {print "\tOutput Path is: $Output\n";}
    if ($Sorules) {print "\tSO Output Path is: $Sorules\n";}
    if ($Sostubs) {print "\tSO Stub Output Path is: $Sostubs\n";}
    if ($Snort) {print "\tSnort Version is: $Snort\n";}
    if ($Snort_path) {print "\tSnort Path is: $Snort_path\n";}
    if ($Tar_path) {print "\tTar Path is: $Tar_path\n";}
    if ($Snort_config) {print "\tSnort Config File: $Snort_config\n";}
	if ($SID_conf) {print "\tPath to disablesid file: $SID_conf\n";}
    if ($Distro) {print "\tDistro Def is: $Distro\n";}
    if ($Verbose) {print "\tVerbose Flag is Set\n";}
    if ($Verbose == 2) {print "\tExtra Verbose Flag is Set\n";}
    if ($Logging) {print "\tLogging Flag is Set\n";}
    if ($Textonly) {print "\tText Rules only Flag is Set\n";}
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
if (!$Output) {
    $Output = ($Config_info{'rule_path'});
    if (!$Output) {Help();}
}
if (!$Sorules) {
    $Sorules = ($Config_info{'sorule_path'});
}
if (!$Sostubs) {
    $Sostubs = ($Config_info{'sostub_path'});
}
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

# We need a temp path to work with the files while we do magics on them.. make sure you have plenty 
# of space in this path.. ~200mb is a good starting point
$temp_path = ($Config_info{'temp_path'});
if (!$temp_path) {Help();}

#let's fetch the most recent md5 file
if ($oinkcode && $rule_file && -d $temp_path)
{
    # fetch the latest md5 file
    if (!$Hash) {
        md5file($oinkcode,$rule_file,$temp_path);
    }
    #and now lets determine the md5 of the last saved rules file if it exists
    if ( -f "$temp_path/$rule_file" && !$Hash){
        md5sum($rule_file,$temp_path);
    }
    else { # the file didn't exsist so lets get it
        rulefetch($oinkcode,$rule_file,$temp_path);
        if ( -f "$temp_path/$rule_file" && !$Hash){
            md5sum($rule_file,$temp_path);
        }
    }

    # compare the online current md5 against against the md5 of the rules file on system
    compare_md5($oinkcode,$rule_file,$temp_path,$Hash);
    
    if ($Output){
	copy_rules($temp_path,$Output);
    }
    if ($Sorules && $Distro && $Snort && !$Textonly){
	copy_sorules($temp_path,$Sorules,$Distro,$Snort);
	
        # Copy stubs is now deprecated, fast, I know!
        #copy_stubs($temp_path,$Output);
        gen_stubs($Snort_path,$Snort_config,$Sostubs);
    }
} else { Help(); }

if ($temp_path) {
    temp_cleanup();
}
if ($SID_conf && -d $Output) {
	disablesid($SID_conf,$Output,$Sostubs)
}

print ("Fly Piggy Fly!\n");
