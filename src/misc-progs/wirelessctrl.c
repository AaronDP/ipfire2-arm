/* IPCop helper program - wirelessctrl
 *
 * This program is distributed under the terms of the GNU General Public
 * Licence.  See the file COPYING for details.
 *
 * (c) Alan Hourihane, 2003
 * 
 * $Id: wirelessctrl.c,v 1.2.2.5 2005/07/11 10:56:47 franck78 Exp $
 *
 */

#include "libsmooth.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include "setuid.h"
#include <errno.h>

FILE *fd = NULL;
char blue_dev[STRING_SIZE] = "";
char command[STRING_SIZE];

void exithandler(void)
{
  struct keyvalue *kv = NULL;
  char buffer[STRING_SIZE];
	if(strlen(blue_dev))
	{
	 if(findkey(kv, "DROPWIRELESSINPUT", buffer) && !strcmp(buffer,"on")){
	 	snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSINPUT -i %s -j LOG --log-prefix 'DROP_Wirelessinput'", blue_dev);
		safe_system(command);
		}
	 if(findkey(kv, "DROPWIRELESSFORWARD", buffer) && !strcmp(buffer,"on")){
		snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -i %s -j LOG --log-prefix 'DROP_Wirelessforward'", blue_dev);
		safe_system(command);
		}
	 	snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSINPUT -i %s -j DROP -m comment --comment 'DROP_Wirelessinput'", blue_dev);
		safe_system(command);
	 	snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSINPUT -i %s -j DROP -m comment --comment 'DROP_Wirelessforward'", blue_dev);
		safe_system(command);
	}

	if (fd)
		fclose(fd);
}

int main(void)
{
	char green_dev[STRING_SIZE] = "";
	char buffer[STRING_SIZE];
	char *index, *ipaddress, *macaddress, *enabled;
	struct keyvalue *kv = NULL;

	if (!(initsetuid()))
		exit(1);

	/* flush wireless iptables */
	safe_system("/sbin/iptables -F WIRELESSINPUT > /dev/null 2> /dev/null");
	safe_system("/sbin/iptables -F WIRELESSFORWARD > /dev/null 2> /dev/null");

	memset(buffer, 0, STRING_SIZE);

	/* Init the keyvalue structure */
	kv=initkeyvalues();

	/* Read in the current values */
	if (!readkeyvalues(kv, CONFIG_ROOT "/ethernet/settings"))
	{
		fprintf(stderr, "Cannot read ethernet settings\n");
		exit(1);
	}

	/* Read in the firewall values */
	if (!readkeyvalues(kv, CONFIG_ROOT "/optionsfw/settings"))
	{
		fprintf(stderr, "Cannot read optionsfw settings\n");
		exit(1);
	}

	/* Get the GREEN interface details */
	if(!findkey(kv, "GREEN_DEV", green_dev))
	{
		fprintf(stderr, "Cannot read GREEN_DEV\n");
		exit(1);
	}
	if (!VALID_DEVICE(green_dev))
	{
		fprintf(stderr, "Bad GREEN_DEV: %s\n", green_dev);
		exit(1);
	}
	/* Get the BLUE interface details */
	if(!findkey(kv, "BLUE_DEV", blue_dev))
	{
		fprintf(stderr, "Cannot read BLUE_DEV\n");
		exit(1);
	}
	if (strlen(blue_dev) && !VALID_DEVICE(blue_dev))
	{
		fprintf(stderr, "Bad BLUE_DEV: %s\n", blue_dev);
		exit(1);
	}
	if(! strlen(blue_dev) > 0)
	{
		fprintf(stderr, "No BLUE interface\n");
		exit(0);
	}

	/* register exit handler to ensure the block rule is always present */
	atexit(exithandler);

	if (!(fd = fopen(CONFIG_ROOT "/wireless/config", "r")))
	{
		exit(0);
	}
	while (fgets(buffer, STRING_SIZE, fd))
	{
		buffer[strlen(buffer) - 1] = 0;

		index = strtok(buffer, ",");
		ipaddress = strtok(NULL, ",");
		macaddress = strtok(NULL, ",");
		enabled = strtok(NULL, ",");

		if (!strncmp(enabled, "on", 2)) {
		
			/* both specified, added security */
			if ((strlen(macaddress) == 17) && 
			    (VALID_IP(ipaddress))) {
				snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSINPUT -m mac --mac-source %s -s %s -i %s -j ACCEPT", macaddress, ipaddress, blue_dev);
				safe_system(command);
				snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -m mac --mac-source %s -s %s -i %s -o ! %s -j ACCEPT", macaddress, ipaddress, blue_dev, green_dev);
				safe_system(command);
				snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -m mac --mac-source %s -s %s -i %s -j DMZHOLES", macaddress, ipaddress, blue_dev);
				safe_system(command);
			} else {

				/* correctly formed mac address is 17 chars */
				if (strlen(macaddress) == 17) {
					snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSINPUT -m mac --mac-source %s -i %s -j ACCEPT", macaddress, blue_dev);
					safe_system(command);
					snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -m mac --mac-source %s -i %s -o ! %s -j ACCEPT", macaddress, blue_dev, green_dev);
					safe_system(command);
					snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -m mac --mac-source %s -i %s -j DMZHOLES", macaddress, blue_dev);
					safe_system(command);
				}

				if (VALID_IP(ipaddress)) {
					snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSINPUT -s %s -i %s -j ACCEPT", ipaddress, blue_dev);
					safe_system(command);
					snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -s %s -i %s -o ! %s -j ACCEPT", ipaddress, blue_dev, green_dev);
					safe_system(command);
					snprintf(command, STRING_SIZE-1, "/sbin/iptables -A WIRELESSFORWARD -s %s -i %s -j DMZHOLES", ipaddress, blue_dev);
					safe_system(command);
				}
			}
		}
	}

	return 0;
}
