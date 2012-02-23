The Readme is really small, as I assume that you already know how to configure a Squid with SquidGuard as a caching proxy, and that you already have one configured.

To activate the Squid/SquidGuard stuff, open your squid.conf  and configure your squidguard inside (http://squidguard.org) 
All the file are generated in path: resources_path as defined in 'ini/global.ini'


Parameters are:

The squid_conf_path is the path to your Squid/SquidGuard configuration files. This is typically /etc/squid for most installation.

The squid_db_path is the path to your SquidGuard database directory. This is typically /var/lib/squidguard/db for most installation.

The next 2 parameters can be leaved in most of the settings.
The squid_prefix_path is the path prefix. Leave-it empty if you do not need it.
example: squid_prefix_path=/vservers/squid
The squid_prefix_exec is the prefix to execute before reloading line. Leave-it empty if you do not need it, or put simple quote around.
example: squid_prefix_exec='vserver squid exec '


The squid_conf_path parameter is only used for the script deploy_squidguard.sh, nothing else.
Please review it, to check your env and need.
