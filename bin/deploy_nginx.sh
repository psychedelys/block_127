#!/bin/bash

# from https://ajdiaz.wordpress.com/2008/02/09/bash-ini-parser/
cfg.parser ()
{
    local IFS
    ini="$(<$1)"                # read the file
    ini="${ini//[/\[}"          # escape [
    ini="${ini//]/\]}"          # escape ]
    ini="${ini//(/\(}"          # escape (
    ini="${ini//)/\)}"          # escape )
    ini="${ini//;/\;}"          # escape ;
    IFS=$'\n' && ini=( ${ini} ) # convert to line-array
    ini=( ${ini[*]//^#*/} )     # remove comments line with #
    ini=( ${ini[*]/\    =/=} )  # remove tabs before =
    ini=( ${ini[*]/=\   /=} )   # remove tabs be =
    ini=( ${ini[*]/\ =\ /=} )   # remove anything with a space around =
    ini=( ${ini[*]/#\\[/\}$'\n'cfg.section.} ) # set section prefix
    ini=( ${ini[*]/%\\]/ \(} )    # convert text2function (1)
    ini=( ${ini[*]/=/=\( } )    # convert item to array
    ini=( ${ini[*]/%/ \)} )     # close array parenthesis
    ini=( ${ini[*]/%\\ \)/ \\} ) # the multiline trick
    ini=( ${ini[*]/%\( \)/\(\) \{} ) # convert text2function (2)
    ini=( ${ini[*]/%\} \)/\}} ) # remove extra parenthesis
    ini[0]="" # remove first element
    ini[${#ini[*]} + 1]='}'    # add the last brace
    eval "$(echo "${ini[*]}")" # eval the result
}

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd -P`
popd > /dev/null

echo "SCRIPTPATH is ${SCRIPTPATH}"

INIFILE="${SCRIPTPATH}/../ini/global.ini"
echo "INIFILE is ${INIFILE}"

cfg.parser ${INIFILE}
cfg.section.global
 
TMP_PATH=${resources_path}
NGINX_PREFIX_PATH=${nginx_prefix_path}
NGINX_PREFIX_EXEC=${nginx_prefix_exec}
NGINX_CONF_PATH=${nginx_conf_path}
NGINX_CONF_FILE=${nginx_conf_file}

echo "TMP_PATH is ${TMP_PATH}"
echo "NGINX_PREFIX_PATH is ${NGINX_PREFIX_PATH}"
echo "NGINX_CONF_PATH is ${NGINX_CONF_PATH}"
echo "NGINX_CONF_FILE is ${NGINX_CONF_FILE}"
echo "NGINX_PREFIX_EXEC is ${NGINX_PREFIX_EXEC}"

if [ ! -d "${NGINX_PREFIX_PATH}/${NGINX_PATH}" ]; then
  echo "NGINX path ${NGINX_PREFIX_PATH}/${NGINX_PATH} is not found, aborting"
  exit 1
fi


#CONF

echo "Backuping the current Nginx Block config file."

if [ -f "${NGINX_PREFIX_PATH}/${NGINX_CONF_PATH}/${NGINX_CONF_FILE}" ]; then
  cp "${NGINX_PREFIX_PATH}/${NGINX_CONF_PATH}/${NGINX_CONF_FILE}" "${NGINX_PREFIX_PATH}/${NGINX_CONF_PATH}/${NGINX_CONF_FILE}.old"
fi

echo "Copying the new Nginx Block config file."

if [ -f "${TMP_PATH}/nginx_blockips" ]; then
  cp ${TMP_PATH}/nginx_blockips "${NGINX_PREFIX_PATH}/${NGINX_CONF_PATH}/${NGINX_CONF_FILE}"
  echo "Nginx Block conf file is now in \"${NGINX_PREFIX_PATH}/${NGINX_CONF_PATH}/${NGINX_CONF_FILE}\""
else
  echo "New Nginx Block conf files (${NGINX_CONF_FILE}) is not found, exiting";
  exit 1
fi

echo "Now reloading configuration !"

${NGINX_PREFIX_EXEC} nginx -t 
status=$?
if [ ${status} -eq 0 ]; then
  echo "the Config is valid, so now reloading."
else
  echo "The Config is not valid, aborting the reload."
  exit 1;
fi

${NGINX_PREFIX_EXEC} /etc/init.d/nginx reload
