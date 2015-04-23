# Intro #

PulledPork started in April of 2009(and renamed from Baconator in June of '09), this page is really just to list the anticipated(or current) release features....

# Breakin it down... #

v0.6.1 (the Smoking Pig, revisited)

Bug Fixes:
  * [Bug #75](https://code.google.com/p/pulledpork/issues/detail?id=75) - Fixed issue causing output errors when a custom url was used, sub issue was also noted and custom url rules are now prepended with Custom- (see README.CATEGORIES)

v0.6.0 (the Smoking Pig)

New Features / changes:
  * Added -q command line switch to squelch everything except fatal errors
  * Code clean up for readability
  * Move debug output to allow for better debugging of actual variable values
  * Update config to allow for ssl from ET
  * Update config to allow for new snort rules gzip
  * [Bug #55](https://code.google.com/p/pulledpork/issues/detail?id=55) - Create capability to ignore more granularly (plaintext, preproc, shared object or global).
  * [Bug #50](https://code.google.com/p/pulledpork/issues/detail?id=50) - You can now create backups and archives of your existing config and rules files etc...
    * This adds the PM requirement of File::Find
  * [Bug #56](https://code.google.com/p/pulledpork/issues/detail?id=56) - More verbose output when a flowbit is re-enabled (only when run with -v)
  * [Bug #60](https://code.google.com/p/pulledpork/issues/detail?id=60) - added -E flag that will cause ONLY enabled rules to be written to output files
  * [Bug #47](https://code.google.com/p/pulledpork/issues/detail?id=47) - added -R flag that will set the state of the rules specified in enablesid.conf back to their ORIGINAL state, as read from the source rules tarball.
  * [Bug #63](https://code.google.com/p/pulledpork/issues/detail?id=63) - added sid MSG information to changelog output.
  * Added -k and -K options to allow for the writing of the original source file rather than one large output file.
  * [Bug #66](https://code.google.com/p/pulledpork/issues/detail?id=66) - Prepend VRT rulesets with VRT- and ET rulesets with ET- to allow for paralell ruleset operations.  This also provides more granularity in that scenario wherein the user could set state in a VRT or ET category only by specifying VRT-category or ET-category in the sid state modification files.
  * Added support for 500 errors, specifying that users should update their root cert store!

Bug Fixes:
  * [Bug #39](https://code.google.com/p/pulledpork/issues/detail?id=39) - updated to allow for use of username:pass@proxy.url
  * [Bug #49](https://code.google.com/p/pulledpork/issues/detail?id=49) - fix for race condition not allowing HUP to work with -nTH switches specified
  * [Bug #40](https://code.google.com/p/pulledpork/issues/detail?id=40) - allow so\_rules to be handled when non VRT rulesets are downloaded
  * [Bug #45](https://code.google.com/p/pulledpork/issues/detail?id=45) - create a blank so\_stub rules file so that we don't get an error re: a blank file from snort when generating so\_stubs! (only if the file does not already exist, and only if you are using SOs!)
  * [Bug #46](https://code.google.com/p/pulledpork/issues/detail?id=46) - throw error if a config file that is specified does not exist
  * [Bug #42](https://code.google.com/p/pulledpork/issues/detail?id=42) - Added OpenSUSE-11-3 to list
  * Fixed race condition that did not properly handle certain spaces in flowbits set and isset values, resulting in unchecked flowbits etc...
  * [Bug #51](https://code.google.com/p/pulledpork/issues/detail?id=51) - Increased timeout value to 60 seconds
  * [Bug #53](https://code.google.com/p/pulledpork/issues/detail?id=53) - Fixed pcre issue that caused certain rules containing isset and set flobwits values to incorrectly be auto-enabled.
  * [Bug #61](https://code.google.com/p/pulledpork/issues/detail?id=61) - Fixed so that .so rules are not touched!
  * [Bug #67](https://code.google.com/p/pulledpork/issues/detail?id=67) - Fixed regex to allow for space between ( and msg.
  * [Bug #71](https://code.google.com/p/pulledpork/issues/detail?id=71) - Flaw in if statement logic did not allow for proper multiline rule parsing
  * Undocumented ID - Flaw in changelog routine did not allow for proper writing of sid-msg or sid in
> > "deleted rules" section of the changelog.
  * [Bug #62](https://code.google.com/p/pulledpork/issues/detail?id=62) - Added check for amd64 string during arch detection!

Special Notes:
  * [Bug #47](https://code.google.com/p/pulledpork/issues/detail?id=47) - This should be used by advanced users only, it can produce results that may not make sense to the typical user.  And frankly, I don't understand it ;-)
  * [Bug #60](https://code.google.com/p/pulledpork/issues/detail?id=60) - This fix WILL cause inconsistency in your changelog, as when PP reads the old rules from the existing rules file, it will have only the enabled rules in it.. thus any rules that were not enabled in that file will show up as NEW rules in the changelog output, you have been warned, so no whining!

v0.5.0 (the Drowning Rat)

New Features / changes:
  * Automatic VRT tarball name determination (based on local Snort Version)
  * Full support for ET Pro rulesets
  * Full support for new ET Download scheme
  * [Issue #27](https://code.google.com/p/pulledpork/issues/detail?id=#27) Modifysid capability
  * Capability to retrieve multiple rulesets in a single run
  * [Issue #24](https://code.google.com/p/pulledpork/issues/detail?id=#24) Added verbose output showing all requests, results and urls
  * Verbose output now shows percentage bar for downloads
  * Extra Verbose output now shows additional HTTP debug!
  * Set value in default.conf file to https for VRT downloads
  * Set UA Value to (PulledPork/X.X.X)
  * Capability to log critical information to syslog
  * Grabonly option, for those that only want to download the tarball(s)
  * [Issue #34](https://code.google.com/p/pulledpork/issues/detail?id=#34) Added the capability to specify the order of disable / enable / drop
    * using the state\_order configuration option in the master config file
  * Added a contrib directory
  * Added oink-conv.pl to contrib directory
    * converts oinkmaster config files to PP config files
    * Thx Russell Fulton!
  * Added README.CONTRIB to track contrib files (ohai manifest)
  * Perl Modue Requirement Changes (SEE SECTION BELOW)
  * [Issue #38](https://code.google.com/p/pulledpork/issues/detail?id=#38) Added capability to extract reference docs from tarball and store in a defined path, NOTE this dramatically increases PP runtime
    * runtime value is -r

Bug Fixes:
  * Should now correctly use environmentally set proxy settings
    * Shout to pkthound for his work and contribution here!
  * Fixed case where rules with multiple flowbit (un)?set values would not properly populate all of the flowbit values into the rules hash
  * [Bug #29](https://code.google.com/p/pulledpork/issues/detail?id=29) - fixed to allow for proper sid-msg.map generation
  * [Bug #28](https://code.google.com/p/pulledpork/issues/detail?id=28) - fixed numerous spellification issues
  * [Bug #32](https://code.google.com/p/pulledpork/issues/detail?id=32) - fixed to allow for so stub generation in nodownload and !nodownload case


Perl Module Requriement Changes:
  * LWP::Simple no longer
  * LWP::UserAgent now required
  * HTTP::Request now required
  * HTTP::Status now required
  * SYS::Syslog now required
  * Crypt::SSLeay now required
  * Carp now required

v0.4.2

New Features / changes:
  * Capability to modify rules by category (See README.CATEGORIES)
  * Capability to modify rules using regular expressions (pcre:) - See sid modification configs
  * Capability to use regular expressions in specific rule modifications - See sid modification configs
  * Changed the | delimiter for cve,bugtraq etc to :
  * Added README.CATEGORIES
  * Added README.SHAREDOBJECTS
  * Follow flowbit chains
  * Moved README files to doc
  * Automatically determine arch
  * Automatically determine Snort Version
  * Added some verbiage surrounding HUP vs Restart vs When/where/who and how
  * Added support for new snort.org download scheme of http://snort.org/reg-rules...

Bug Fixes:
  * Certain rules specific GID values were not being properly parsed by the modifysid sub.
  * [Bug #20](https://code.google.com/p/pulledpork/issues/detail?id=20) fixed, ranges are no longer off by +1 additional rule being enabled
  * Enhancement request #21, added more descript information to dropsid.conf and to README
  * Fixed flaw that caused certain flowbits to not be set (when GID boundaries were crossed and multiple keys were checked)
  * Enhancement request #22 updated the master config file to contain all of the currently available precompiled SO rules
  * Remove risky system calls, use handles instead

v0.4.1 (Stumbling Leprechaun)

New Features/changes:
  * Flowbit tracking! - This means that all flowbits are not enabled when a specific base ruleset is specified (security etc...) but rather all flowbits are now tracked, allowing for only those that are required to be enabled.
  * Adjusted pulledpork.conf to account for new snort rules tarball naming and packing scheme, post Snort 2.8.6 release.
  * Added option to specify all rule modification files in the master pulledpork.conf file - feature request 19.
  * Added capability to specify base ruleset (see README.RULESETS) in master pulledpork.conf file.
  * Handle preprocessor and sensitive-information rulesets

Bug Fixes:
  * 18 - non-rule lines containing the string sid:xxxx were being populated into the rule data structure, added an extra check to ensure that this does not occur
  * Cleaned up href pointers, syntatical purposes only...
  * Modified master config to allow for better readability on smaller console based systems
  * Error output was not always returning full error, fixed this

BE SURE to read through the master pulledpork.conf file thoroughly, as
there are many changes as of snort 2.8.6.0 that WILL affect you, even
if you are NOT yet running 2.8.6.0!

v0.4.0 (Drunken Leprechaun)

This version constitutes a major rewrite of the rule reading, modification
and writing system to improve speed, future module addition, supportability,
and of course reliability.

New Features/changes:
  * Enablesid
  * Moved all .conf files under etc/
  * Ability to define sid ranges in any of the sid modification .conf files
  * Ability to specify references in any of the sid modification .conf files
  * Ability to ignore entire rule categories (i.e. not include them)
  * Specify locally stored rules files that need their meta data included in sid-msg.map
  * All rulestate modifications, comparisons etc.. are now handled in-memory
  * Rewrite of sid-msg.map generation code to allow for all proper character reading and addition to sid-msg.map
  * No longer reliant on tar binary, now using Archive::Tar
  * Ability to specify your arch for so\_rules
  * Added significant amounts of debug output when an error is detected
  * Rules are now written to only two distinct files

Bug Fixes:
  * Properly account for whitespace in non-standard rulesets such as ET
  * Cleaned up and improved the changelog to display new / deleted sids and rule totals
  * Certian conditions caused the md5 check to fail even when valid - This was primarily an ET issue, but did manifest on VRT rulesets also
  * Many small fixes that were not tracked well :-P
  * Do not overwrite local.rules, but still include in sid-msg.map generation

Release 0.3.4:
  * Support metadata based VRT recommended rulesets
  * Maintain an optional rule changelog
  * Support for setting rules to Drop
  * Bugfix for certain MD5 related issues
  * Support for multi-line rules
  * Speed enhancements
  * Additional error handling and throwing

Release 0.2.5:
  * Option to use Emerging-Threats rules or specify a custom url
  * More automation!
  * Bugfixes
  * Speed / code cleanup

Release 0.2:
  * Rule modification, i.e. disabling of specific rules within rule sets
  * Outputs changes in rules files if any rules have been added / modified
  * Compares new rules files with current rule sets
  * Automated retrieval of certain variables (Distro, Snort Version.. etc)

Release 0.1:
  * First **Beta** Release
  * Downloads latest rules file
  * Verifies MD5 of local rules file
  * If MD5 has not changed from snort.org.. doesn't fetch files again
  * handle both rules and so\_rules
  * Capability to generate stub files

Next Release...
  * TBD by community needs / requests, one example is the capability to compile SO rules