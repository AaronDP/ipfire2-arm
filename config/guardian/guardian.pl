#!/usr/bin/perl
# based on V 1.7 guardian enhanced for IPFire and snort 2.8
# Read the readme file for changes
#
# Enhanced for IPFire by IPFire Team
# Added Portscan detection for non syslog system
# Added SSH-Watch for SSH-Bruteforce Attacks
# An suppected IP will be blocked on all interfaces

use Getopt::Std;

$guardianctrl = "/usr/local/bin/guardianctrl";

# Array to store information about ignored networks.
my @ignored_networks = ();

# Hash to store IP addresses and their current state.
my %blockhash = ();

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

# Setup signal handler.
&sig_handler_setup;

&debugger("My ip address and interface are: $hostipaddr $interface\n");

if ($hostipaddr !~ /\d+\.\d+\.\d+\.\d+/) {
	print "This ip address is bad : $hostipaddr\n";
	die "I need a good host ipaddress\n";
}

$networkaddr = $hostipaddr;
$networkaddr =~ s/\d+$/0/;
$gatewayaddr = `cat /var/ipfire/red/remote-ipaddress 2>/dev/null`;
$broadcastaddr = $hostipaddr;
$broadcastaddr =~ s/\d+$/255/;

# Generate hash for ignored hosts or networks.
&build_ignore_hash;


&debugger("My gatewayaddess is: $gatewayaddr\n");

# This is the target hash. If a packet was destened to any of these, then the
# sender of that packet will get denied, unless it is on the ignore list..

%targethash = ( "$networkaddr" => 1,
	"$broadcastaddr" => 1,
	"0" => 1,	# This is what gets sent to &checkem if no
			# destination was found.
	"$hostipaddr" => 1);

&get_aliases;

if ( -e $targetfile ) {
	&load_targetfile;
}

# Check if we are running in debug mode or we can deamonize.
if (defined($opt_d)) {
	&debugger("Running in debug mode...\n");
} else {
	&daemonize;
}

open (ALERT, $alert_file) or die "can't open alert file: $alert_file: $!\n";
seek (ALERT, 0, 2); # set the position to EOF.
# this is the same as a tail -f :)
open (SYSLOG, "/var/log/messages" ) or die "can't open /var/log/messages: $!\n";
seek (SYSLOG, 0, 2); # set the position to EOF.
# this is the same as a tail -f :)
open (HTTPDLOG, "/var/log/httpd/error_log" ) or die "can't open /var/log/httpd/error_log: $!\n";
seek (HTTPDLOG, 0, 2); # set the position to EOF.
# this is the same as a tail -f :)
$counter=0;

for (;;) {
	sleep 1;
	if (seek(ALERT,0,1)) {
		while (<ALERT>) {
			chop;
			if (defined($opt_d)) {
				print "$_\n";
			}
			if (/\[\*\*\]\s+(.*)\s+\[\*\*\]/) {
				$type=$1;
			}
			if (/(\d+\.\d+\.\d+\.\d+):\d+ -\> (\d+\.\d+\.\d+\.\d+):\d+/) {
				&checkaction ($1, $2, $type);
			}
			if (/(\d+\.\d+\.\d+\.\d+)+ -\> (\d+\.\d+\.\d+\.\d+)+/) {
				&checkaction ($1, $2, $type);
			}
		}
	}

	if (seek(SYSLOG,0,1)) {
		while (<SYSLOG>) {
			chop;
			if ($_=~/.*sshd.*Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*/) {
				&checkaction ($1, "", "possible SSH-Bruteforce Attack");}

			# This should catch Bruteforce Attacks with enabled preauth
			if ($_ =~ /.*sshd.*Received disconnect from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):.*\[preauth\]/) {
				&checkaction ($1, "", "possible SSH-Bruteforce Attack, failed preauth");}
			}
	}

	if (seek(HTTPDLOG,0,1)){
		while (<HTTPDLOG>) {
			chop;
			# This should catch Bruteforce Attacks on the WUI
			if ($_ =~ /.*\[error\] \[client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] user(.*) not found:.*/) {
				&checkaction ($1, "", "possible WUI-Bruteforce Attack, wrong user" .$2);
			}

			if ($_ =~ /.*\[error\] \[client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] user(.*): authentication failure for.*/) {
				&checkaction ($1, "", "possible WUI-Bruteforce Attack, wrong password for user" .$2);
			}
		}
	}

# Run this stuff every 30 seconds..
	if ($counter == 30) {
		&remove_blocks; # This might get moved elsewhere, depending on how much load
				# it puts on the system..
		&check_log_name;
		&check_log_ssh;
		&check_log_http;
		$counter=0;
	} else {
		$counter=$counter+1;
	}
}

sub check_log_name {
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
	$atime,$mtime,$ctime,$blksize,$blocks) = stat($alert_file);
	if ($size < $previous_size) {	     # The filesize is smaller than last
		close (ALERT);               # we checked, so we need to reopen it
		open (ALERT, "$alert_file"); # This should still work in our main while
		$previous_size=$size;        # loop (I hope)
		&debugger("Log filename changed. Reopening $alert_file\n");
	} else {
		$previous_size=$size;
	}
}

sub check_log_ssh {
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
	$atime,$mtime,$ctime,$blksize,$blocks) = stat("/var/log/messages");
	if ($size < $previous_size_ssh) {			# The filesize is smaller than last
		close (SYSLOG);					# we checked, so we need to reopen it
		open (SYSLOG, "/var/log/messages");		# This should still work in our main while
		$previous_size_ssh=$size;			# loop (I hope)
		&debugger("Log filesize changed. Reopening /var/log/messages\n");
	} else {
		$previous_size_ssh=$size;
	}
}

sub check_log_http {
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
	$atime,$mtime,$ctime,$blksize,$blocks) = stat("/var/log/httpd/error_log");
	if ($size < $previous_size_http) {			# The filesize is smaller than last
		close (HTTPDLOG);					# we checked, so we need to reopen it
		open (HTTPDLOG, "/var/log/httpd/error_log");	# This should still work in our main while
		$previous_size_http=$size;			# loop (I hope)
		&debugger("Log filesize changed. Reopening /var/log/httpd/error_log\n");
	} else {
		$previous_size_http=$size;
	}
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

sub load_conf {
	if ($opt_c eq "") {
		$opt_c = "/etc/guardian/guardian.conf";
	}

	if (! -e $opt_c) {
		die "Need a configuration file.. please use to the -c option to name a configuration file\n";
	}

	open (CONF, $opt_c) or die "Cannot read the config file $opt_c, $!\n";
	while (<CONF>) {
		chop;
		next if (/^\s*$/); #skip blank lines
		next if (/^#/); # skip comment lines
		if (/LogFile\s+(.*)/) {
			$logfile = $1;
		}
		if (/Interface\s+(.*)/) {
			$interface = $1;
			if ( $interface eq "" ) {
				$interface = `cat /var/ipfire/ethernet/settings | grep RED_DEV | cut -d"=" -f2`;
			}
		}
		if (/AlertFile\s+(.*)/) {
			$alert_file = $1;
		}
		if (/IgnoreFile\s+(.*)/) {
			$ignorefile = $1;
		}
		if (/TargetFile\s+(.*)/) {
			$targetfile = $1;
		}
		if (/TimeLimit\s+(.*)/) {
			$TimeLimit = $1;
		}
		if (/HostIpAddr\s+(.*)/) {
			$hostipaddr = $1;
		}
		if (/HostGatewayByte\s+(.*)/) {
			$hostgatewaybyte = $1;
		}
	}
	
	if ($alert_file eq "") {
		&debugger("Warning! AlertFile is undefined.. Assuming /var/log/snort.alert\n");
		$alert_file="/var/log/snort.alert";
	}
	if ($hostipaddr eq "") {
		&debugger("Warning! HostIpAddr is undefined! Attempting to guess..\n");
		$hostipaddr = `cat /var/ipfire/red/local-ipaddress`;
		&debugger("Got it.. your HostIpAddr is $hostipaddr\n");
	}
	if ($ignorefile eq "") {
		&debugger("Warning! IgnoreFile is undefined.. going with default ignore list (hostname and gateway)!\n");
	}
	if ($hostgatewaybyte eq "") {
		&debugger("Warning! HostGatewayByte is undefined.. gateway will not be in ignore list!\n");
	}
	if ($logfile eq "") {
		print "Warning! LogFile is undefined.. Assuming debug mode, output to STDOUT\n";
		$opt_d = 1;
	}
	if (! -w $logfile) {
		print "Warning! Logfile is not writeable! Engaging debug mode, output to STDOUT\n";
		$opt_d = 1;
	}

	if (! -e $guardianctrl) {
		print "Error! Could not find $guardianctrl. Exiting. \n";
		exit;
	}

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

sub get_aliases {
	my $ip;
	&debugger("Scanning for aliases on $interface and add them to the target hash...\n");

	open (IFCONFIG, "/sbin/ip addr show $interface |");
	my @lines = <IFCONFIG>;
	close(IFCONFIG);

	foreach $line (@lines) {
		if ( $line =~ /inet (\d+\.\d+\.\d+\.\d+)/) {
			$ip = $1;
			&debugger("Got $ip on $interface ...\n");
			$targethash{'$ip'} = "1";
		}
	}
}

# this sub converts a dotted IP to a decimal IP
sub ip2dec ($) {
	unpack N => pack CCCC => split /\./ => shift;
}
