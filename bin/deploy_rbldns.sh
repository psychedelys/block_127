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
RBLDNS_PREFIX_PATH=${rbldns_prefix_path}
RBLDNS_PREFIX_EXEC=${rbldns_prefix_exec}
RBLDNS_CONF_PATH=${rbldns_db_path}
RBLDNS_CONF_FILE=rbldns_bad_guys

echo "TMP_PATH is ${TMP_PATH}"
echo "RBLDNS_PREFIX_PATH is ${RBLDNS_PREFIX_PATH}"
echo "RBLDNS_CONF_PATH is ${RBLDNS_CONF_PATH}"
echo "RBLDNS_PREFIX_EXEC is ${RBLDNS_PREFIX_EXEC}"

if [ ! -d "${RBLDNS_PREFIX_PATH}/${RBLDNS_PATH}" ]; then
  echo "RBLDNS path ${RBLDNS_PREFIX_PATH}/${RBLDNS_PATH} is not found, aborting"
  exit 1
fi


#CONF

echo "Backuping the current RBLdns config file."

if [ -f "${RBLDNS_PREFIX_PATH}/${RBLDNS_CONF_PATH}/${RBLDNS_CONF_FILE}" ]; then
  cp "${RBLDNS_PREFIX_PATH}/${RBLDNS_CONF_PATH}/${RBLDNS_CONF_FILE}" "${RBLDNS_PREFIX_PATH}/${RBLDNS_CONF_PATH}/${RBLDNS_CONF_FILE}.old"
fi

echo "Copying the new RBLdns Block config file."

if [ -f "${TMP_PATH}/${RBLDNS_CONF_FILE}" ]; then
  cp "${TMP_PATH}/${RBLDNS_CONF_FILE}" "${RBLDNS_PREFIX_PATH}/${RBLDNS_CONF_PATH}/${RBLDNS_CONF_FILE}"
  echo "RBLdns Block conf file is now in \"${RBLDNS_PREFIX_PATH}/${RBLDNS_CONF_PATH}/${RBLDNS_CONF_FILE}\""
else
  echo "New RBLdns Block conf files (${RBLDNS_CONF_FILE}) is not found, exiting";
  exit 1
fi

echo "Now reloading configuration !"

${RBLDNS_PREFIX_EXEC} /etc/init.d/rbldnsd reload
