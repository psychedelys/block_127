The Readme is really small, as I assume that you already know how to configure a RBL DNS daemon and that you already have one configured.

All the file are generated in path: resources_path as defined in 'ini/global.ini'


Parameters are:

### RBLDNS

# rbldns_ip is the ip where the rbldns is bind to. Change-it to your need.
rbldns_ip=10.10.10.52

# rbldns_conf_path is the path to your RBLDNS configuration files.
rbldns_conf_path=/etc/rbldns

# rbldns_db_path is the path to your RBLDNS database directory.
rbldns_db_path=/var/lib/rbldns/dsbl

The next 2 parameters can be leaved in most of the settings.

The rbldns_prefix_path is the path prefix. Leave-it empty if you do not need it.
The rbldns_prefix_exec is the prefix to execute before reloading line. Leave-it empty if you do not need it, or put simple quote around.

In the case of virtualisation with Linux-vserver:
rbldns_prefix_path=/vservers/rbldns
rbldns_prefix_exec='vserver rbldns exec'

#### few more words:

Do not forgot to add the DNS Stuff.

; subdomain delegation
rbl.exemple.org.  in ns rbl.exemple.org.
rbl.exemple.org.  in a 10.10.10.52


zone "rbl.exemple.org" IN {
   type forward;
   forward first;
   forwarders { 10.10.10.52; };
};

The config file might look like something like that:

/etc/default/rbldnsd

# My boot rbldnsd options
# -----------------------------------------
# TTL 35m, check files every 60s for changes, -f = smooth reloads
# -l logfilepath
# Please change 10.10.10.52 to your real public IP that you want the dns daemon to listen on
# Please change exemple.org to your real domain name.
#
RBLDNSD="dsbl -l /var/log/rbldns/rbl.log -f -r/var/lib/rbldns/dsbl -b 10.10.10.52 \
   rbl.exemple.org:ip4set:rbldns_bad_guys \
   rbl.exemple.org:generic:forward
"

# and the associated directory:

mkdir /var/lib/rbldns/dsbl
touch /var/lib/rbldns/dsbl/forward
mkdir /var/log/rbldns
touch /var/log/rbldns/rbl.log
chown -R rbldns:rbldns /var/lib/rbldns/dsbl


cat /var/lib/rbldns/dsbl/forward
@ A 10.10.10.52
test A 10.10.10.52

cat /var/lib/rbldns/dsbl/rbldns_bad_guys
[... The generated files ...]

# Testing
nslookup test.rbl.exemple.org
# Testing one of the ip in the blacklist: 89.40.1.32
nslookup 32.1.40.89.rbl.exemple.org
127.0.0.2

Also, other options available could be: http://www.blue-quartz.com/rbl/

or also add other rbldns to your RBL dns server.
# rsync -tvPz rsync.dsbl.org::dsbl/rbldns-list.dsbl.org /var/db/rbldnsd/rbldns-list.dsbl.org
# rsync -tvPz rsync-mirrors.uceprotect.net::RBLDNSD-ALL/dnsbl-1.uceprotect.net /var/db/rbldnsd/dnsbl- 1.uceprotect.net
# rsync -tvPz rsync.spamcannibal.org::zonefiles/bl.spamcannibal.org.in.ip4set.rbl /var/db/rbldnsd/bl.spamcannibal.org.in.ip4set.rbl

If you need more information on how-to configure RBL DNS deamon, you might want to check your distrib, your friends, your DuckDuckGo.com,...
