The Readme is really small, as I assume that you already know how to configure a nginx as a websever, and that you already have one configured.

To activate the Nginx stuff, open your nginx.conf  and configure inside your configuration an include directory to the generated files. The default name is 'blockips.conf'.
All the file are generated in path: resources_path, and the default nginx block file name is: nginx_conf_file as defined in 'ini/global.ini'

Parameters are:

The nginx_conf_path is the path to your nginx configuration files. This is typically /etc/nginx for most installation.

The nginx_conf_file is the name of the file which you are including. By convention this is blockips.conf, located in the nginx_conf_path directory.

The next 2 parameters can be leaved in most of the settings.

The nginx_prefix_path is the path prefix. Leave-it empty if you do not need it.
The nginx_prefix_exec is the prefix to execute before reloading line. Leave-it empty if you do not need it, or put simple quote around.
nginx_prefix_exec=

In the case of virtualisation with Linux-vserver:
nginx_prefix_path=/vservers/nginx
nginx_prefix_exec='vserver nginx exec '

The nginx parameters are only used for the script deploy_nginx.sh, nothing else.
Please review it, to check your env and need.
