#!/bin/sh
# This file is part of the Fail2ban Report (fail2ban-report) package
# (c) BestPractise.net <info-at-bestpractise.net>
#
# View README and CHANGELOG distributed with this code for more information.
#
# This is a wrapper script around the fail2ban-client of fail2ban. It is used
# to able to securely authorize PHP via sudo to execute the requested commands.
if [ "$1" = "status" ]; then
	sudo fail2ban-client status
elif [ "$1" = "loglevel" ]; then
	sudo fail2ban-client get loglevel
elif [ "$1" = "logtarget" ]; then
	sudo fail2ban-client get logtarget
elif [ "$1" = "syslogsocket" ]; then
	sudo fail2ban-client get syslogsocket
elif [ "$1" = "dbfile" ]; then
	sudo fail2ban-client get dbfile
elif [ "$1" = "dbpurgeage" ]; then
	sudo fail2ban-client get dbpurgeage
elif [ "$1" = "jail" ]; then
	if [ "$2" = "bantime" ]; then
		sudo fail2ban-client get $3 bantime
	elif [ "$2" = "findtime" ]; then
		sudo fail2ban-client get $3 findtime
	elif [ "$2" = "ignoreip" ]; then
		sudo fail2ban-client get $3 ignoreip
	elif [ "$2" = "ignoreself" ]; then
		sudo fail2ban-client get $3 ignoreself
	elif [ "$2" = "journalmatch" ]; then
		sudo fail2ban-client get $3 journalmatch
	elif [ "$2" = "logencoding" ]; then
		sudo fail2ban-client get $3 logencoding
	elif [ "$2" = "logpath" ]; then
		sudo fail2ban-client get $3 logpath
	elif [ "$2" = "maxlines" ]; then
		sudo fail2ban-client get $3 maxlines
	elif [ "$2" = "maxretry" ]; then
		sudo fail2ban-client get $3 maxretry
	elif [ "$2" = "usedns" ]; then
		sudo fail2ban-client get $3 usedns
	fi
else
	echo "No args given"
fi
