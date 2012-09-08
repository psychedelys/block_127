The Readme is really small, as I assume that you already know how to configure a Bind as DNS cache, and that you already have one configured.

All the file are generated in path: resources_path as defined in 'ini/global.ini'


Parameters are:

The bind_path is the path to your Bind configuration files. This is typically /etc/bind for no chroot, and /jail/bind/etc for chroot env.

The bind_path parameters is only used for the script deploy_binddns.sh, nothing else.
Please review it, to check your env and need.



To activate the Bind stuff, open your named.conf 

You might have some stuff like:
--%<-->%--
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
include "/etc/bind/named.conf.logging";
--%<-->%--

So you need to add a new line like where named.conf.block is the conf file that we have generated:
--%<-->%--
include "/etc/bind/named.conf.block";
--%<-->%--

If you need more information on how-to configure Bind as a local cache deamon, you might want to check your distrib, your friends, your DuckDuckGo.com,...
