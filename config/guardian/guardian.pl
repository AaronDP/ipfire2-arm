#!/usr/bin/perl
# based on V 1.7 guardian enhanced for IPFire and snort 2.8
# Read the readme file for changes
#
# Enhanced for IPFire by IPFire Team
# Added Portscan detection for non syslog system
# Added SSH-Watch for SSH-Bruteforce Attacks
# An suppected IP will be blocked on all interfaces

use Getopt::Std;
use Thread::Queue;
use Linux::Inotify2;

$General::swroot = '/var/ipfire';
require "${General::swroot}/general-functions.pl";
require "${General::swroot}/network-functions.pl";

# Path to guardianctrl.
$guardianctrl = "/usr/local/bin/guardianctrl";

# Default values.
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

# Hash to store IP addresses and their current state.
my %blockhash = ();

# Hast to store the last read position of a file.
# This hash will be used to seek to the last known position and
# get latest appenden entries.
my %fileposition = ();

# Option parser for given arguments from command line.
&getopts ('hc:d');
if (defined($opt_h)) {
	print "Guardian v1.7 \n";
	print "guardian.pl [-hd] <-c config>\n";
	print " -h  shows help\n";
	print " -d  run in debug mode (doesn't fork, output goes to STDOUT)\n";
	print " -c  specifiy a configuration file other than the default (/etc/guardian/guardian.conf)\n";
	exit;
}

# Call function to read in the configuration file.
&load_conf;

# Update array for monitored_files after the config file has been loaded.
my @monitored_files = ( "$syslogfile",
			"$alert_file",
			"$httpdlog_file" );

# Setup signal handler.
&sig_handler_setup;

# Get host address.
my $hostipaddr = &get_address("$redaddress_file");

# Check if we got an address, otherwise we have to cancel here.
if (! $hostipaddr) {
	die "Invalid $hostipaddr. Cannot go further!\n";
}
&debugger("My host IP-address is: $hostipaddr\n");

# Get gateway address.
my $gatewayaddr = &get_address("$gatewayaddress_file");
&debugger("My gatewayaddess is: $gatewayaddr\n");

# Calculate networkaddress and broadcast addresses.
my $networkaddr = $hostipaddr;
my $networkaddr =~ s/\d+$/0/;
my $broadcastaddr = $hostipaddr;
my $broadcastaddr =~ s/\d+$/255/;

# Generate hash for ignored hosts or networks.
&build_ignore_hash;

# This is the target hash. If a packet was sent to any of these addresses, then the
# sender of that packet will get denied, unless it is on the ignore list..
my %targethash = (
		"$networkaddr" => 1,
		"$broadcastaddr" => 1,
		"0" => 1,	# This is what gets sent to &checkem if no destination was found.
		"$hostipaddr" => 1 );

# Get alias addresses on red.
&get_aliases;

# Load targetfile if given by the configfile.
if ( -e $targetfile ) {
	&load_targetfile;
}

# Gather file positions.
&init_fileposition;

# Setup file watcher.
&create_watcher;

# Create queue for processing inotify events.
my $queue = new Thread::Queue or die "Could not create new, empty queue. $!\n";

# Check if we are running in debug mode or we can deamonize.
if (defined($opt_d)) {
	&debugger("Running in debug mode...\n");
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
	if (defined($current_elements)) {
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
		&checkaction ($1, "", "possible SSH-Bruteforce Attack");
	}

	# This should catch Bruteforce Attacks with enabled preauth
	elsif ($message =~ /.*sshd.*Received disconnect from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):.*\[preauth\]/) {
		&checkaction ($1, "", "possible SSH-Bruteforce Attack, failed preauth");
	}
}

#
## Function to parse snort alerts.
#
sub handle_snort (@) {
	my @alert = @_;

	# Loop through the given array and parse the lines.
	foreach my $line (@alert) {
		if ($line =~ /\[\*\*\]\s+(.*)\s+\[\*\*\]/) {
			$type=$1;
		}

		# Look for a line like xxx.xxx.xxx.xxx:xxx -> xxx.xxx.xxx.xxx:xxx
		elsif ($line =~ /(\d+\.\d+\.\d+\.\d+):\d+ -\> (\d+\.\d+\.\d+\.\d+):\d+/) {
			&checkaction ($1, $2, $type);
		}

		# Search for a line like xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx
		elsif ($line =~ /(\d+\.\d+\.\d+\.\d+)+ -\> (\d+\.\d+\.\d+\.\d+)+/) {
			&checkaction ($1, $2, $type);
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
		&checkaction ($1, "", "possible WUI-Bruteforce Attack, wrong user" .$2);
	}

	# Detect Password brute-forcing.
	elsif ($message =~ /.*\[error\] \[client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] user(.*): authentication failure for.*/) {
		&checkaction ($1, "", "possible WUI-Bruteforce Attack, wrong password for user" .$2);
	}
}

#
## Function to create inotify tasks for each monitored file.
#
sub create_watcher {
	our $watcher = new Linux::Inotify2 or die "Could not use inotify. $!\n";

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

sub checkaction {
	my ($source, $dest, $type) = @_;
	my $flag=0;

	# Do nothing if the source allready has been blocked.
	return 0 if ($blockhash{$source} > 4);

	# Check if the source address equals the hosts ip address.
	# This will prevent us from nuking ourselves.
	return 1 if ($source eq $hostipaddr);

	# Check if the source equals our gateway.
	return 1 if ($source eq $gatewayaddr);

	# Watch if the source address is part of our ignore list.
	if ($ignore{$source} == 1) { # check our ignore list..
		&logger("$source\t$type\n");
		&logger("Ignoring attack because $source is in my ignore list\n");
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
			&logger("$source\t$type\n");
			&logger("Ignoring attack because $source is part of an ignored network\n");
			return 1;
		}
	}

	# Look if the offending packet was sent to us, the network, or the broadcast and block the
	# attacker.
	if ($targethash{$dest} == 1) {
		&ipchain ($source, $dest, $type);
	}

	if ( $blockhash{$source} == 4 ) {
		&logger("Source = $source, blocking for $target attack.\n");
		&ipchain ($source, "", $type);
		$blockhash{$source} = $blockhash{$source}+1;
		return 0;
	}

	# Start counting for new source addresses.
	if ($blockhash{$source} eq "") {
		$blockhash{$source} = 1;
		&debugger("$source\t$type\n");
		&debugger("Start counting for source = $source\n");
		return 0;
	}

	# Increase counting of existing addresses.
	$blockhash{$source} = $blockhash{$source}+1;
	&debugger("$source\t$type\n");
	&debugger("Source = $source count $blockhash{$source} - No action done yet.\n");
}

sub ipchain {
	my ($source, $dest, $type) = @_;
	&debugger("$source\t$type\n");
	if ($hash{$source} eq "") {
		&debugger("Running '$guardianctrl block $source'\n");
		system ("$guardianctrl block $source");
		$hash{$source} = time() + $TimeLimit;
	} else {
# We have already blocked this one, but snort detected another attack. So
# we should update the time blocked..
		$hash{$source} = time() + $TimeLimit;
	}
}

sub build_ignore_hash {
	#  This would cause is to ignore all broadcasts if it
	#  got set.. However if unset, then the attacker could spoof the packet to make
	#  it look like it came from the network, and a reply to the spoofed packet
	#  could be seen if the attacker were on the local network.

	#  $ignore{$networkaddr}=1;

	# same thing as above, just with the broadcast instead of the network.

	#  $ignore{$broadcastaddr}=1;

	my $count =0;
	my @subnets;

	$ignore{$gatewayaddr}=1;
	$ignore{$hostipaddr}=1;
	if ($ignorefile ne "") {
		open (IGNORE, $ignorefile);
		while (<IGNORE>) {
			$_=~ s/\s+$//;
			chomp;
			next if (/\#/);  #skip comments
			next if (/^\s*$/); # and blank lines

			# Check if we got a single address or a subnet.
			if (/\//) {

				# Add enty to our subnet array.
				push(@subnets, $_);

			} else {

				# Add single address to the ignore hash.
				$ignore{$_}=1;
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
		&debugger("Loaded $count entries from $ignorefile\n");

		# Return ignored_networks array.
		return @ignored_networks;

	} else {

		# Handle empty or missing ignorefile.
		&debugger("No ignore file was loaded!\n");
	}
}

#
## Function to parse the configuration file.
#
sub load_conf {
	# Detect if a different than the default file should be load.
	if ($opt_c eq "") {
		$opt_c = "/etc/guardian/guardian.conf";
	}

	# Check if the given configuration file or the default one exists and can be read.
	if (! -e $opt_c) {
		die "Need a configuration file.. please use to the -c option to name a configuration file\n";
	}

	# Open the file.
	open (CONF, $opt_c) or die "Cannot read the config file $opt_c, $!\n";
	while (<CONF>) {
		chop;

		# Skip blank lines.
		next if (/^\s*$/);

		# Skip comments.
		next if (/^#/);

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

		# Read path to the targetfile.
		if (/TargetFile\s+(.*)/) {
			$targetfile = $1;
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
		&debugger("Warning! IgnoreFile is undefined.. going with default ignore list (hostname and gateway)!\n");
	}

	# Check the HostGatewayByte has been set.
	if ($hostgatewaybyte eq "") {
		&debugger("Warning! HostGatewayByte is undefined.. gateway will not be in ignore list!\n");
	}

	# Check if a path for the LogFile has been given.
	if ($logfile eq "") {
		print "Warning! LogFile is undefined.. Assuming debug mode, output to STDOUT\n";
		$opt_d = 1;
	}

	# Check if our logfile is writeable.
	if (! -w $logfile) {
		print "Warning! Logfile is not writeable! Engaging debug mode, output to STDOUT\n";
		$opt_d = 1;
	}

	# Check if guardianctrl is available.
	if (! -e $guardianctrl) {
		print "Error! Could not find $guardianctrl. Exiting. \n";
		exit;
	}

	# Check if a TimeLimit has been provided or set to default.
	if ($TimeLimit eq "") {
		&debugger("Warning! Time limit not defined. Defaulting to absurdly long time limit\n");
		$TimeLimit = 999999999;
	}
}

#
## Function to write messages to guardians logfile.
#
sub logger {
	my $message = $_[0];
	my $date = localtime();

	# Open Logfile.
	open (LOG, ">>$logfile");

	# Append message.
	print LOG $date.": ".$message;

	# Close the file afterwards.
	close (LOG);

	# Also print send to STDOUT if we are running in debug mode.
	&debugger("$message");
}

#
## Function to write debug content to STDOUT.
#
sub debugger {
	my $message = $_[0];

	# Only write to STDOUT if debug mode has been enabled.
	if (defined($opt_d)) {
		# Print out to STDOUT.
		print STDOUT $message;
	}
}

sub daemonize {
	my ($home);
 	if (fork()) {
# parent
		exit(0);
	} else {
# child
		&debugger("Guardian process id $$\n");
		$home = (getpwuid($>))[7] || die "No home directory!\n";
		chdir($home);                   # go to my homedir
		setpgrp(0,0);                   # become process leader
		close(STDOUT);
		close(STDIN);
		close(STDERR);
		print "Testing...\n";
	}
}

sub sig_handler_setup {
	$SIG{INT} = \&clean_up_and_exit; # kill -2
	$SIG{TERM} = \&clean_up_and_exit; # kill -9
	$SIG{QUIT} = \&clean_up_and_exit; # kill -3
#  $SIG{HUP} = \&flush_and_reload; # kill -1
}

sub remove_blocks {
	my $source;
	my $time = time();
	foreach $source (keys %hash) {
		if ($hash{$source} < $time) {
			&call_unblock ($source, "expiring block of $source\n");
			delete ($hash{$source});
		}
	}
}

sub call_unblock {
	my ($source, $message) = @_;
	&debugger("$message");
	system ("$guardianctrl unblock $source");
}

sub clean_up_and_exit {
	my $source;
	&debugger("received kill sig.. shutting down\n");
	foreach $source (keys %hash) {
		&call_unblock ($source, "removing $source for shutdown\n");
	}
	exit;
}

sub load_targetfile {
	my $count = 0;
	open (TARG, "$targetfile") or die "Cannot open $targetfile\n";
	while (<TARG>) {
		chop;
		next if (/\#/);  #skip comments
		next if (/^\s*$/); # and blank lines
		$targethash{$_}=1;
		$count++;
	}
	close (TARG);
	&logger("Loaded $count addresses from $targetfile\n");
}

#
## Function to get alias addresses on red interface.
## Add them to the target hash.
#
sub get_aliases {
	my $ip;

	&debugger("Scanning for aliases on $interface and add them to the target hash...\n");

	# Get name of the red interface.
	my $interface = &General::get_red_interface;

	# Use shell ip command to get additional addresses.
	open (IFCONFIG, "/sbin/ip addr show $interface |");
	my @lines = <IFCONFIG>;
	close(IFCONFIG);

	# Add grabbed addresses to target hash.
	foreach $line (@lines) {
		if ( $line =~ /inet (\d+\.\d+\.\d+\.\d+)/) {
			$ip = $1;
			&debugger("Got $ip on $interface ...\n");
			$targethash{'$ip'} = "1";
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
