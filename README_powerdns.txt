The Readme is really small, as I assume that you already know how to configure a PowerDNS as DNS cache, and that you already have one configured.

All the file are generated in path: resources_path as defined in 'ini/global.ini'


Parameters are:

The powerdns_path is the path to your PowerDNS configuration files reside. This is typically /etc/powerdns.

The powerdns_path parameters is only used for the script deploy_powerdns.sh, nothing else.
Please review it, to check your env and need.



To activate the PowerDNS stuff, edit your configuration  

You might have some stuff like:
--%<-->%--
launch=gsqlite3:first
gsqlite3-first-database=/etc/powerdns/sqlite/db.sqlite3
--%<-->%--

If you need more information on how-to configure PowerDNS as a local cache deamon, you might want to check your distrib, your friends, your DuckDuckGo.com,...
