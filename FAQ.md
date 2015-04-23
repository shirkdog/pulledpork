# Introduction #

Below you will find answers to the most commonly asked questions.


# FAQs #

**How do I use PP?**
  * Download the latest tarball
  * Follow the instructions in the README and PullePork.conf
  * Modify your snort.conf to only use the snort.rules (and so\_rules.rules if using SO rules) file(s)
  * Run PulledPork
  * Start snort

**When I run PP, I get a 500 error and something about Certificate Authority or verification about SSL Peers**
  * install or update Mozilla::CA IO::Socket::SSL
    * Will fix it most times. The Mozilla::CA installs/updates the perl root certificates and IO::Socket::SSL enables ssl verification by hostname in Crypt::SSLeay.
  * Update your trusted root certificates on your OS, consult the documentation for your OS to do this.
  * Alternately you can change the url to http from https for your snortrules tarball.

**When I run PP, I get a 501 error and PP ends**
  * Install Crypt::SSLeay either from CPAN
  * Install Crypt::SSLeay from a package (on Ubuntu libcrypt-ssleay-perl)
  * You may also need to install LWP::Protocol::https
  * Be sure that your root certificates are up to date (google this for your distro!)
  * If you use a proxy, be sure both HTTP and HTTPS\_PROXY values are set (see below)
  * Run PP with the extra verbose options -vv and review the output for the exact source of the error

**I have a proxy, how I can make pulledpork use my proxy?**
  * You need to set the appropriate environment variable (perl has this built in)
  * HTTP\_PROXY=http://foo:bar@192.0.2.0:3128
  * HTTPS\_PROXY=http://foo:bar@192.0.2.0:3128
  * Run pulledpork (this can be done via cron also)!

**When I run pulledpork, it keeps displaying the help but not parsing my rules?**
  * Ensure LWP::Simple is installed properly (perl -MCPAN -e shell 'install LWP::Simple')
  * Verify that your output paths all exist and are writable by the calling user
  * Verify that you are using the latest version of the config file that came with the  version of pulledpork that you are running!

**When I run pulledpork, I get a 403 error**
  * If you are a subscriber, be sure that your subscription has not expired.
  * If you are a registered user, there is a 15 minute timeout period that must timeout before you can download rules again.

**When I run pulledpork, I get an error about LWP::Simple?**
  * Ensure LWP::Simple is installed properly (perl -MCPAN -e shell 'install LWP::Simple')

**When I run pulledpork, I get an error about Archive::Tar?**
  * Ensure Archive::Tar is installed properly (perl -MCPAN -e shell 'install Archive::Tar')

**I run Emerging Threats rulesets or custom rulesets and not all messages are in sid-msg.map and my pulledpork version is 0.3.4**
  * Download the <a href='http://pulledpork.googlecode.com/files/pp_304_whitespace.patch'>pp_304_whitespace.patch</a> file and apply to your pulledpork.pl code
  * More info here <a href='http://global-security.blogspot.com/2010/01/et-rules-and-s.html'>global-security.blogspot.com</a>.