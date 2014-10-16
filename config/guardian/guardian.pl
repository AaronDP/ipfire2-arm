#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2014  IPFire Development Team                                 #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

# Inspired by the idea of guardian from http://www.chaotic.org/guardian/
#
# Rewritten and massively enhanced by the IPFire Development Team.

use Getopt::Std;
use Thread::Queue;
use Linux::Inotify2;
use strict;

$General::swroot = '/var/ipfire';
require "${General::swroot}/general-functions.pl";
require "${General::swroot}/network-functions.pl";

# Used variables and default values..
my $configfile = "$General::swroot/guardian/guardian.conf";
my $ignorefile;
my $loglevel;
my $logfile;

my $TimeLimit = "86400";
my $hostgatewaybyte = "1";

our $watcher;

# Path to guardianctrl.
my $guardianctrl = "/usr/local/bin/guardianctrl";

# Watched files.
my $syslogfile = "/var/log/messages";
my $alert_file = "/var/log/snort.alert";
my $httpdlog_file = "/var/log/httpd/error_log";

# Files for red and gateway addresses.
my $redaddress_file = "/var/ipfire/red/local-ipaddress";
my $gatewayaddress_file = "/var/ipfire/red/remote-ipaddress";

# Array to store information about ignored networks.
my @ignored_networks = ();

# Array to store the monitored files.
my @monitored_files = ();

# Hash to store the given command line options.
my %options = ();

# Hash to store all supported loglevels.
my %loglevels = (
	"off" => 0,
	"info" => 1,
	"debug" => 2
);

# Hash to store IP addresses and their current state.
my %addresshash = ();

# Hash to store blocked addresses and the remaining time.
my %blockhash = ();

# Hash to store ignored addresses.
my %ignorehash = ();

# Hast to store the last read position of a file.
# This hash will be used to seek to the last known position and
# get latest appenden entries.
my %fileposition = ();

# Option parser for given arguments from command line.
&getopts ("hc:d", \%options);
if (defined($options{"h"})) {
	print "Guardian v2.0 \n";
	print "guardian.pl [-hd] <-c config>\n";
	print " -h  shows help\n";
	print " -d  run in debug mode (doesn't fork, output goes to STDOUT)\n";
	print " -c  specifiy a configuration file other than the default (/etc/guardian/guardian.conf)\n";
	exit;
}

# Call function to read in the configuration file.
&load_conf;

# Update array for monitored_files after the config file has been loaded.
my @monitored_files = (
	"$syslogfile",
	"$alert_file",
	"$httpdlog_file"
);

# Setup signal handler.
&sig_handler_setup;

# Get host address.
my $hostipaddr = &get_address("$redaddress_file");

# Check if we got an address, otherwise we have to cancel here.
if (! $hostipaddr) {
	die "Invalid $hostipaddr. Cannot go further!\n";
}
&logger("debug", "My host IP-address is: $hostipaddr\n");

# Get gateway address.
my $gatewayaddr = &get_address("$gatewayaddress_file");
&logger("debug", "My gatewayaddess is: $gatewayaddr\n");

# Generate hash for ignored hosts or networks.
&build_ignore_hash;

# Get alias addresses on red.
&get_aliases;

# Gather file positions.
&init_fileposition;

# Setup file watcher.
&create_watcher;

# Create queue for processing inotify events.
my $queue = new Thread::Queue or die "Could not create new, empty queue. $!\n";

# Check if we are running in debug mode or we can deamonize.
if (defined($options{"d"})) {
	&logger("debug", "Running in debug mode...\n");
} else {
	&daemonize;
}

#
## Main loop.
#
while () {
	# Read inotify events.
	my @events = $watcher->read;

	# Put the inotify  events into the queue.
	$queue->enqueue(@events);

	# Get the amount of elements in our queue.
	# "undef" is returned if it is empty.
	my $current_elements = $queue->pending();

	# Check if our queue contains some elements.
	if ($current_elements > 0) {
		# Grab element data from queue.
		my $element = $queue->peek();

		# Get changed file.
		my $changed_file = $element->fullname;

		# Gather last lastposition of the file from hash.
		my $position = $fileposition{$changed_file};

		# Open the file.
		open (FILE, $changed_file) or die "Could not open $changed_file. $!\n";

		# Seek to the last position.
		seek (FILE, $position, 0);

		# A snort alert contains more than one line.
		my @alert = ();
		my $message;

		if ($changed_file eq "$alert_file") {
			# Loop through alert file until the complete alert has
			# read in.
			while (my $line = <FILE>) {
				# Remove newlines.
				chomp $line;

				# Add lines to our array.
				push(@alert, $line);
			}
		# Logfiles with a single line are pretty easy to handle.
		} else {
			# Get log message.
			my $message = <FILE>;

			# Remove newline.
			chomp $message,
		}

		# Get new file position.
		my $new_position = tell(FILE);

		# Update hash.
		$fileposition{$changed_file} = $new_position;

		# Close the file.
		close(FILE);

		# Use responsible handler based on the modified file.
		if ("$changed_file" eq "$syslogfile") {
			&handle_ssh("$message");
		}
		elsif ("$changed_file" eq "$alert_file") {
			&handle_snort(@alert);
		}
		elsif ("$changed_file" eq "$httpdlog_file") {
			&handle_httpd("$message");
		}

		# Drop processed event from queue.
		$queue->dequeue();
	}
	# Call subroutine to check if the block time of
	# any address has expired.
	&remove_blocks;
}

#
# ----- Subroutines -----
#

#
## Function to detect SSH-Bruteforce Attacks.
#
sub handle_ssh ($) {
	my $message = $_[0];

	# Check for failed password attempts.
	if ($message =~/.*sshd.*Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*/) {
		&checkaction ($1, "Possible SSH-Bruteforce Attack.");
	}

	# This should catch Bruteforce Attacks with enabled preauth
	elsif ($message =~ /.*sshd.*Received disconnect from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):.*\[preauth\]/) {
		&checkaction ($1, "Possible SSH-Bruteforce Attack - failed preauth.");
	}
}

#
## Function to parse snort alerts.
#
sub handle_snort (@) {
	my @alert = @_;

	# Loop through the given array and parse the lines.
	foreach my $line (@alert) {
		# Look for a line like xxx.xxx.xxx.xxx:xxx -> xxx.xxx.xxx.xxx:xxx
		if ($line =~ /(\d+\.\d+\.\d+\.\d+):\d+ -\> (\d+\.\d+\.\d+\.\d+):\d+/) {
			&checkaction ($1, "An active snort rule has matched and gained an alert.");
		}

		# Search for a line like xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx
		elsif ($line =~ /(\d+\.\d+\.\d+\.\d+)+ -\> (\d+\.\d+\.\d+\.\d+)+/) {
			&checkaction ($1, "An active snort rule has matched and gained an alert.");
		}
	}
}

#
## Function to detect HTTPD Login-Bruteforce attempts.
#
sub handle_httpd ($) {
	my $message = $_[0];

	# This should catch Bruteforce Attacks on the WUI
	if ($message =~ /.*\[error\] \[client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] user(.*) not found:.*/) {
		&checkaction ($1, "Possible WUI-Bruteforce Attack, wrong user" .$2);
	}

	# Detect Password brute-forcing.
	elsif ($message =~ /.*\[error\] \[client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] user(.*): authentication failure for.*/) {
		&checkaction ($1, "Possible WUI-Bruteforce Attack, wrong password for user" .$2);
	}
}

#
## Function to create inotify tasks for each monitored file.
#
sub create_watcher {
	$watcher = new Linux::Inotify2 or die "Could not use inotify. $!\n";

	foreach my $file (@monitored_files) {
		$watcher->watch("$file", IN_MODIFY) or die "Could not monitor $file. $!\n";
	}
}

#
## Function to init the filepositions for each monitored file.
## The information will be stored in a hash and easily can be
## accessed again.
#
sub init_fileposition {
	foreach my $file (@monitored_files) {
		# Open the file.
		open(FILE, $file) or die "Could not open $file. $!\n";

		# Seek to the end of file (EOF).
		seek(FILE, 0, 2);

		# Get the position.
		my $position = tell(FILE);

		# Store position into the positon hash.
		$fileposition{$file} = $position;

		# Close the file.
		close(FILE);
	}

	return %fileposition;
}

#
## Function to check wich action should performed for a given event.
#
sub checkaction {
	my ($source, $message) = @_;

	# Do nothing if the source allready has been blocked.
	return 0 if ($addresshash{$source} > 4);

	# Check if the source address equals the hosts ip address.
	# This will prevent us from nuking ourselves.
	return 1 if ($source eq $hostipaddr);

	# Check if the source equals our gateway.
	return 1 if ($source eq $gatewayaddr);

	# Watch if the source address is part of our ignore list.
	if ($ignorehash{$source} == 1) {
		&logger("info", "Ignoring attack because $source is in my ignore list!\n");
		return 1;
	}

	# Move through our ignored_networks array and check if the address is a part of one.
	foreach my $network (@ignored_networks) {

		# Get the network ranges.
		my $first = @$network[0];
		my $last = @$network[1];

		# Convert source into 32bit decimal format.
		my $src = &ip2dec($source);

		# Check if $source addres is part of an ignored network.
		if (($src >= $first) && ($src <= $last)) {
			# Write out log messages.
			&logger("info", "Ignoring attack because $source is part of an ignored network\n");
			return 1;
		}
	}

	# Check if the "source" reached our blocking count (4).
	if ( $addresshash{$source} == 4 ) {
		# Write out log message.
		&logger("info", "Blocking $source: $message\n");

		# Block the source address.
		&call_block($source);

		# Update the addresshash.
		$addresshash{$source} = $addresshash{$source}+1;
		return 0;
	}
	# Start counting for new source addresses.
	elsif ($addresshash{$source} eq "") {
		# Set addresshash to "1".
		$addresshash{$source} = 1;

		&logger("debug", "Start counting for $source\n");
		return 0;
	} else {
		# Increase counting of existing addresses.
		$addresshash{$source} = $addresshash{$source}+1;
		&logger("debug", "Source $source count $addresshash{$source} - No action done yet.\n");
	}
}

#
## Function to generate the ignore hash.
#
sub build_ignore_hash {
	my $count =0;
	my @subnets;

	# Add our gatewayaddress and hostipaddr to the ignore hash.
	$ignorehash{$gatewayaddr}=1;
	$ignorehash{$hostipaddr}=1;

	# Read-in the file if an ignorefile has been provided.
	if ($ignorefile ne "") {
		open (IGNORE, $ignorefile) or die "Could not open $ignorefile. $!\n";
		while (<IGNORE>) {
			$_=~ s/\s+$//;
			chomp;

			# Skip comments.
			next if (/\#/);

			# Skip blank lines.
			next if (/^\s*$/);

			# Check if we got a valid single address.
			if (&Network::check_ip_address($_)) {
				# Add single address to the ignore hash.
				$ignorehash{$_}=1;
			}
			# Check if the input contains a valid address and mask.
			elsif (&Network::check_network($_)) {
				# Add enty to our subnet array.
				push(@subnets, $_);

			} else {
				# Ignore the invalid input.
				next;
			}

			$count++;
		}
		close (IGNORE);

		# Generate required values for ignored_networks array.
		foreach my $subnet (@subnets) {

			# Splitt subnet into net and mask parts.
			# The first part (@split[0]) will contain the network information,
			# the secont part (@split[1]) the subnetmask.
			my @split = split(/\//, $subnet);

			# Convert network into 32bit decimal format.
			my $net = &ip2dec(@split[0]);

			# Check if the subnetmask has been given as dot decimal notation or as a prefix
			# and convert it into 32bit decimal format.
			my $mask = @split[1];
			if ( $mask =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/ ) {
				$mask = &ip2dec($mask);
			} else {
				$mask = -1<<(32-$mask);
			}

			# Generate address space based on the given details.
			my $first = $net & $mask;
			my $last = $first | ~$mask;

			# Append generated result to our ignored_networks array.
			push(@ignored_networks, [$first, $last]);
		}

		# Write out log message.
		&logger("debug", "Loaded $count entries from $ignorefile\n");

		# Return ignored_networks array.
		return @ignored_networks;

	} else {

		# Handle empty or missing ignorefile.
		&logger("debug", "No ignore file was loaded!\n");
	}
}

#
## Function to parse the configuration file.
#
sub load_conf {
	# Detect if a different than the default file should be load.
	if ($options{"c"} ne "") {
		my $configfile = $options{"c"};
	}

	# Check if the given configuration file or the default one exists and can be read.
	if (! -e $configfile) {
		die "Need a configuration file.. please use to the -c option to name a configuration file\n";
	}

	# Open the file.
	open (CONF, $configfile) or die "Cannot read the config file $configfile, $!\n";
	while (<CONF>) {
		chop;

		# Skip blank lines.
		next if (/^\s*$/);

		# Skip comments.
		next if (/^#/);

		# Get loglevel.
		if (/LogLevel\s+(.*)/) {
			$loglevel = $1;
		}

		# Read-in path to logfile.
		if (/LogFile\s+(.*)/) {
			$logfile = $1;
		}

		# Get path to snort alert file.
		if (/AlertFile\s+(.*)/) {
			$alert_file = $1;
		}

		# Omit path to the ignorefile.
		if (/IgnoreFile\s+(.*)/) {
			$ignorefile = $1;
		}

		# Get timelimit for blocktime.
		if (/TimeLimit\s+(.*)/) {
			$TimeLimit = $1;
		}

		# HostGatewayByte for automatically adding the gateway to
		# the ignore hash.
		if (/HostGatewayByte\s+(.*)/) {
			$hostgatewaybyte = $1;
		}
	}

	# Validate input.
	#
	# Check if an ignorefile has been defined.
	if ($ignorefile eq "") {
		&logger("debug", "Warning! IgnoreFile is undefined.. going with default ignore list (hostname and gateway)!\n");
	}

	# Check if a valid LogLevel has been given or use default one (info).
	if(!$loglevels{$loglevel}) {
		$loglevel = "info";
	}

	# Check if a path for the LogFile has been given.
	if ($logfile eq "") {
		print "Warning! LogFile is undefined.. Assuming debug mode, output to STDOUT\n";
		$loglevel = "debug";
		$options{"d"} = 1;
	}

	# Check if our logfile is writeable.
	if (! -w $logfile) {
		print "Warning! Logfile is not writeable! Engaging debug mode, output to STDOUT\n";
		$loglevel = "debug";
		$options{"d"} = 1;
	}

	# Check if guardianctrl is available.
	if (! -e $guardianctrl) {
		print "Error! Could not find $guardianctrl. Exiting. \n";
		exit;
	}
}

#
## Function to handle logging.
#
## This function requires two arguments: The required loglevel and
## the message itself. The required loglevel will be compared with the
## current one to gather if the given message should be logged or ignored.
#
sub logger {
	my ($level, $message) = @_;

	if(!$loglevels{$level}) {
		&logger("debug", "The logger has been called with an invalid loglevel ($level)!\n");
		return;
	}

	# Get value for the current used loglevel.
	my $current_level = $loglevels{$loglevel};

	# Get value for the required loglevel.
	my $required_level = $loglevels{$level};

	# Check if the message should be handled.
	if ($current_level >= $required_level) {
		# Check if we are running in debug mode or we should
		# log to a logfile.
		if (((defined($options{"d"}))) || ($logfile eq "")) {
			# Print out to STDOUT.
			print STDOUT $message;
		} else {
			# Get date.
			my $date = localtime();

			# Open Logfile.
			open (LOG, ">>$logfile") or die "Could not open $logfile for writing. $!\n";

			# Append message.
			print LOG $date.": ".$message;

			# Close the file afterwards.
			close (LOG);
		}
	}
}

#
## Function to daemonize guardian.
#
sub daemonize {
	my $home;

	# Daemonize guardian.
	my $pid = fork();

	# Die if we got no process id returned.
	if ($pid < 0) {
		die "Could not fork: $!\n";
	}
	# Everything done.
	elsif ($pid) {
		exit 0;
	}
}

#
## Function for capturing process signals.
#
sub sig_handler_setup {
	$SIG{INT} = \&clean_up_and_exit; # kill -2
	$SIG{TERM} = \&clean_up_and_exit; # kill -9
	$SIG{QUIT} = \&clean_up_and_exit; # kill -3
	$SIG{HUP} = \&reload_on_sighup; # kill -1
}

#
## Function to handle sighup events.
#
sub reload_on_sighup {
	# Print out log message.
	&logger("info", "Recived SIGHUP signal - Reloading configfile and recreate the ignorelist.\n");

	# Reload config file.
	&load_conf;

	# Rebuild ignorehash.
	&build_ignore_hash;

	# Grab alias adresses on red.
	&get_aliases;
}

#
## Function to determine if the bocktime of an address has been expired.
#
sub remove_blocks {
	my $address;

	# Get current time.
	my $time = time();

	# Loop through the current blocked addresses.
	foreach $address (keys %blockhash) {
		# Check if the time for the address has expired.
		if ($blockhash{$address} < $time) {
			# Call unblock.
			&logger("info", "Block time for $address has expired\n");
			&call_unblock($address);

			# Drop address from blockhash.
			delete ($blockhash{$address});
		}
	}
}

#
## Function to block a given address and set counter for unblocking.
#
sub call_block ($) {
	my $address = $_[0];

	# Generate time when the block will expire.
	my $expire = time() + $TimeLimit;

	# Check if the address currently is not blocked.
	if ($blockhash{"$address"} eq "") {
		# Call guardianctrl to block the address.
		system("$guardianctrl block $address");
	}

	# Store/update the generated expire time.
	$blockhash{$address} = $expire;
}

#
## Function to unblock a given address.
#
sub call_unblock ($) {
	my $address = $_[0];

	# Call guardianctrl to unblock the address.
	system ("$guardianctrl unblock $address");
}

#
## Subroutine to handle shutdown of the programm.
sub clean_up_and_exit {
	&logger("debug", "Received KILL signal - Shutting down\n");

	# Unblock all currently blocked addresses.
	foreach my $address (keys %blockhash) {
		# Unblock the address.
		&logger("debug", "Removing $address for shutdown\n");
		&call_unblock ($address);
	}
	exit;
}

#
## Function to get alias addresses on red interface.
## Add them to the ignore hash to prevent from nuking our selfes.
#
sub get_aliases {
	my $ip;

	# Get name of the red interface.
	my $interface = &General::get_red_interface;

	&logger("debug", "Scanning for aliases on $interface and add them to the ignore hash...\n");

	# Use shell ip command to get additional addresses.
	open (IFCONFIG, "/sbin/ip addr show $interface |");
	my @lines = <IFCONFIG>;
	close(IFCONFIG);

	# Add grabbed addresses to the ignore hash.
	foreach my $line (@lines) {
		if ( $line =~ /inet (\d+\.\d+\.\d+\.\d+)/) {
			$ip = $1;

			# Check if the address is valid.
			if (&Network::check_ip_address($ip)) {
				&logger("debug", "Got $ip on $interface ...\n");
				$ignorehash{"ip"}=1;
			}
		}
	}
}

#
## Function to get an IP-address from a given file.
## The IP-address has to be part of the first line.
#
sub get_address ($) {
	my $file = $_[0];

	# Open the given file.
	open (FILE, "$file") or die "Could not open $file. $!\n";

	# Get address.
	my $address = <FILE>;

	# Close file.
	close (FILE);

	# Removing newlines.
	chomp $address;

	# Check if the grabbed address is valid.
	if (&Network::check_ip_address($address)) {
		return $address;
	}

	return;
}

# this sub converts a dotted IP to a decimal IP
sub ip2dec ($) {
	unpack N => pack CCCC => split /\./ => shift;
}
