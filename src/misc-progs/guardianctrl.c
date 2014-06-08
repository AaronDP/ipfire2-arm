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
#include "netutil.h"

const char *chain = "GUARDIAN";

int main(int argc, char *argv[]) {
	char cmd[STRING_SIZE];

        if (!(initsetuid()))
                exit(1);

        if (argc < 2) {
                fprintf(stderr, "\nNo argument given.\n\nguardianctrl (start|stop|restart|get-chain|flush-chain|block|unblock)\n\n");
                exit(1);
        }
	if (strcmp(argv[1], "start") == 0) {
		safe_system("/etc/rc.d/init.d/guardian start");

	} else if (strcmp(argv[1], "stop") == 0) {
		safe_system("/etc/rc.d/init.d/guardian stop");

	} else if (strcmp(argv[1], "restart") == 0) {
		safe_system("/etc/rc.d/init.d/guardian restart");

	} else if (strcmp(argv[1], "get-chain") == 0) {
		snprintf(cmd, sizeof(cmd), "/sbin/iptables -n -v -L %s", chain);
                safe_system(cmd);

        } else if (strcmp(argv[1], "flush-chain") == 0) {
		snprintf(cmd, sizeof(cmd), "/sbin/iptables -F %s", chain);
                safe_system(cmd);

        } else if (strcmp(argv[1], "block") == 0) {
		if (argc == 3) {
			char* ipaddress = argv[2];
			if ((!VALID_IP(ipaddress)) && (!VALID_IP_AND_MASK(ipaddress))) {
				fprintf(stderr, "A valid IP address or subnet is required.\n");
				exit(1);
			}

			snprintf(cmd, sizeof(cmd), "/sbin/iptables -I %s -s %s -j DROP", chain, ipaddress);
			safe_system(cmd);
		} else {
			fprintf(stderr, "\nTo few arguments. \n\nUSAGE: guardianctrl block <address>\n\n");
			exit(1);
		}
        } else if (strcmp(argv[1], "unblock") == 0) {
		if (argc == 3) {
			char* ipaddress = argv[2];
			if ((!VALID_IP(ipaddress)) && (!VALID_IP_AND_MASK(ipaddress))) {
				fprintf(stderr, "A valid IP address or subnet is required.\n");
				exit(1);
			}

			snprintf(cmd, sizeof(cmd), "/sbin/iptables -D %s -s %s -j DROP", chain, ipaddress);
			safe_system(cmd);
		} else {
			fprintf(stderr, "\nTo few arguments. \n\nUSAGE: guardianctrl unblock <address>\n\n");
			exit(1);
		}
        } else {
                fprintf(stderr, "\nBad argument given.\n\nguardianctrl (start|stop|restart|get-chain|flush-chain|block|unblock)\n\n");
                exit(1);
        }

        return 0;
}
