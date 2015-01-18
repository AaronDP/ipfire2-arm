/* This file is part of the IPFire Firewall.
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include "setuid.h"
#include "netutil.h"

const char *chain = "GUARDIAN";
const char *pidfile = "/run/guardian.pid";

int main(int argc, char *argv[]) {
	char cmd[STRING_SIZE];

        if (!(initsetuid()))
                exit(1);

        if (argc < 2) {
                fprintf(stderr, "\nNo argument given.\n\nguardianctrl (start|stop|restart|reload|get-chain|flush-chain|block|unblock)\n\n");
                exit(1);
        }
	if (strcmp(argv[1], "start") == 0) {
		safe_system("/etc/rc.d/init.d/guardian start");

	} else if (strcmp(argv[1], "stop") == 0) {
		safe_system("/etc/rc.d/init.d/guardian stop");

	} else if (strcmp(argv[1], "restart") == 0) {
		safe_system("/etc/rc.d/init.d/guardian restart");

	} else if (strcmp(argv[1], "reload") == 0) {
		reloadDaemon();

	} else if (strcmp(argv[1], "get-chain") == 0) {
		snprintf(cmd, sizeof(cmd), "/sbin/iptables --wait -n -v -L %s", chain);
                safe_system(cmd);

        } else if (strcmp(argv[1], "flush-chain") == 0) {
		snprintf(cmd, sizeof(cmd), "/sbin/iptables --wait -F %s", chain);
                safe_system(cmd);

        } else if (strcmp(argv[1], "block") == 0) {
		if (argc == 3) {
			char* ipaddress = argv[2];
			if ((!VALID_IP(ipaddress)) && (!VALID_IP_AND_MASK(ipaddress))) {
				fprintf(stderr, "A valid IP address or subnet is required.\n");
				exit(1);
			}

			snprintf(cmd, sizeof(cmd), "/sbin/iptables --wait -I %s -s %s -j DROP >/dev/null 2>&1", chain, ipaddress);
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

			snprintf(cmd, sizeof(cmd), "/sbin/iptables --wait -D %s -s %s -j DROP >/dev/null 2>&1", chain, ipaddress);

			// Loop to be sure that all entries for an address will be dropped from chain
			// Loop limit: 10 rounds
			int limit;

			limit = 0;
			while(limit++ < 10) {
				int retval = safe_system(cmd);

				// Leave loop if we got a different return code than "0"
				if (retval > 0) {
					break;
				}
			}
		} else {
			fprintf(stderr, "\nTo few arguments. \n\nUSAGE: guardianctrl unblock <address>\n\n");
			exit(1);
		}
        } else {
                fprintf(stderr, "\nBad argument given.\n\nguardianctrl (start|stop|restart|reload|get-chain|flush-chain|block|unblock)\n\n");
                exit(1);
        }

        return 0;
}

/* Function to perfom a reload of guardian, by sending a SIGHUP signal to the process.
 * The process id directly will be read from the defined pidfile. */
void reloadDaemon(void) {
	FILE *file = NULL;

	// Open the pidfile.
	file = fopen(pidfile, "r");

	// Exit if the file could not opened.
	if (file == NULL) {
		fprintf(stderr, "Could not open %s for reading.\n", pidfile);
		exit(1);
	}

	int pid = 0;

	// Read the process id from the file.
	if(fscanf(file, "%d", &pid) <= 0) {
		fprintf(stderr, "Invalid data from pidfile (%s).\n", pidfile);
		exit(1);
	}

	// Close the pidfile.
	fclose(file);

	// Send a SIGHUP to the process.
	if(kill(pid, SIGHUP) != 0) {
		fprintf(stderr, "Could not execute kill(): %s\n", strerror(errno));
		exit(1);
	}

	return 0;
}
