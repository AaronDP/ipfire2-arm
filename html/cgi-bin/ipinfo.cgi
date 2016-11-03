#!/usr/bin/perl
###############################################################################
#                                                                             #
# IPFire.org - A linux based firewall                                         #
# Copyright (C) 2010  IPFire Team  <info@ipfire.org>                          #
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

use CGI;
use IO::Socket;
use strict;

# enable only the following on debugging purpose
#use warnings;
#use CGI::Carp 'fatalsToBrowser';

require '/var/ipfire/general-functions.pl';
require "${General::swroot}/lang.pl";
require "${General::swroot}/header.pl";
require "${General::swroot}/geoip-functions.pl";

my %cgiparams=();

&Header::showhttpheaders();

&Header::openpage($Lang::tr{'ip info'}, 1, '');
&Header::openbigbox('100%', 'left');
my @lines=();
my $extraquery='';

my $addr = CGI::param("ip") || "";

if (&General::validip($addr)) {
	$extraquery='';
	@lines=();
	my $whoisname = "whois.arin.net";
	my $iaddr = inet_aton($addr);
	my $hostname = gethostbyaddr($iaddr, AF_INET);
	if (!$hostname) { $hostname = $Lang::tr{'lookup failed'}; }

	# Obtain the country code for the given IP-address.
	my $ccode = &GeoIP::get_ccode_by_address($addr);

	# Get full country name.
	my $cname = &GeoIP::get_full_country_name($ccode);

	# Get flag icon for of the country.
	my $flag_icon = &GeoIP::get_flag_icon($ccode);

	my $sock = new IO::Socket::INET ( PeerAddr => $whoisname, PeerPort => 43, Proto => 'tcp');
	if ($sock)
	{
		print $sock "n $addr\n";
		while (<$sock>) {
			$extraquery = $1 if (/ReferralServer: whois:\/\/(\S+)\s+/);
			push(@lines,$_);
		}
		close($sock);
		if ($extraquery) {
			undef (@lines);
			$whoisname = $extraquery;
			my $sock = new IO::Socket::INET ( PeerAddr => $whoisname, PeerPort => 43, Proto => 'tcp');
			if ($sock)
			{
				print $sock "$addr\n";
				while (<$sock>) {
					push(@lines,$_);
				}
			}
			else
			{
				@lines = ( "$Lang::tr{'unable to contact'} $whoisname" );
			}
		}
	}
	else
	{
		@lines = ( "$Lang::tr{'unable to contact'} $whoisname" );
	}
	&Header::openbox('100%', 'left', $addr .
		' <img src=\'' . $flag_icon . '\' border=\'0\' align=\'absmiddle\' alt=\'' .$cname .'\' title=\'' . $cname . '\'>
		(' . $hostname . ') : '. $whoisname . '
	');

	print<<END;

	<table width="50%" border="0">
		<tr>
			<td class="base" width="30%"><b>$Lang::tr{'ip reputational info'}</b></td>
			<td class="base" width="20%" align="center">
				<a href="http://www.ipvoid.com/scan/$addr" target="_blank">
					<img src="/images/ipvoid.ico" title="IpVoid" border="0"> IPVoid
				</a>
			</td>
			<td class="base" width="20%" align="center">
				<a href="https://www.virustotal.com/en/ip-address/$addr/information" target="_blank">
					<img src="/images/virustotal.ico" title="VirusTotal" border="0" /> VirusTotal
				</a>
			</td>
			<td class="base" width="20%" align="center">
				<a href="http://multirbl.valli.org/lookup/$addr.html" target="_blank">
					<img src="/images/rbl.jpg" title="MultiRBL" border="0" /> MultiRBL
				</a>
			</td>
		</tr>
	</table>
	<br><br>
END

	print "<pre>\n";
	foreach my $line (@lines) {
		print &Header::cleanhtml($line,"y");
	}
	print "</pre>\n";
	&Header::closebox();
} else {
	&Header::openbox('100%', 'left', $Lang::tr{'invalid ip'});
	print <<EOF;
		<p style="text-align: center;">
			$Lang::tr{'invalid ip'}
		</p>
EOF
	&Header::closebox();
}

print <<END
<div align='center'>
<table width='80%'>
<tr>
	<td align='center'><a href='$ENV{'HTTP_REFERER'}'>$Lang::tr{'back'}</a></td>
</tr>
</table>
</div>
END
;

&Header::closebigbox();

&Header::closepage();
