#!/bin/bash
############################################################################################
# Version 0.1a, Copyright (C) 2006  Peter Schaelchli F�r IPFire besteht KEINERLEI GARANTIE;#
# IPFire ist freie Software, die Sie unter bestimmten Bedingungen weitergeben d�rfen;      #
############################################################################################

# Conf File festlegen
CONF_File=/opt/pakfire/pakfire.conf

if [ -r $CONF_File ]
then 
 STRI=$(grep $1 $CONF_File)
 STRI=${STRI#*=}
fi

if [ -z $2 ]
 then echo "$STRI"
 else cat $STRI
fi

################################### EOF ####################################################
