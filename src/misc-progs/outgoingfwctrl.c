/* This file is part of the IPFire Firewall.
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "setuid.h"

int main(int argc, char *argv[]) {

	if (!(initsetuid()))
		exit(1);

	safe_system("chmod 755 /var/ipfire/outgoing/bin/outgoingfw.pl");
	safe_system("/var/ipfire/outgoing/bin/outgoingfw.pl");
	return 0;
}
