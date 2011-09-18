#!/bin/bash
############################################################################
#                                                                          #
# This file is part of the IPFire Firewall.                                #
#                                                                          #
# IPFire is free software; you can redistribute it and/or modify           #
# it under the terms of the GNU General Public License as published by     #
# the Free Software Foundation; either version 2 of the License, or        #
# (at your option) any later version.                                      #
#                                                                          #
# IPFire is distributed in the hope that it will be useful,                #
# but WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
# GNU General Public License for more details.                             #
#                                                                          #
# You should have received a copy of the GNU General Public License        #
# along with IPFire; if not, write to the Free Software                    #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA #
#                                                                          #
# Copyright (C) 2007 IPFire-Team <info@ipfire.org>.                        #
#                                                                          #
############################################################################
#
. /opt/pakfire/lib/functions.sh

extract_files

# Create download directories if they do not yet exist.
mkdir -p /var/transmission/{downloads,incomplete} 2>/dev/null

# Adjust permissions.
chown nobody.nobody /etc/transmission /var/transmission

# Start the service.
/etc/init.d/transmission start

ln -sf ../init.d/transmission /etc/rc.d/rc0.d/K20transmission
ln -sf ../init.d/transmission /etc/rc.d/rc3.d/S99transmission
ln -sf ../init.d/transmission /etc/rc.d/rc6.d/K20transmission

exit 0
