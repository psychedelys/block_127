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
SQUID_PREFIX_PATH=${squid_prefix_path}
SQUID_PREFIX_EXEC=${squid_prefix_exec}
SQUID_CONF_PATH=${squid_conf_path}
SQUID_DB_PATH=${squid_db_path}

echo "TMP_PATH is ${TMP_PATH}"
echo "SQUID_PREFIX_PATH is ${SQUID_PREFIX_PATH}"
echo "SQUID_CONF_PATH is ${SQUID_CONF_PATH}"
echo "SQUID_DB_PATH is ${SQUID_DB_PATH}"
echo "SQUID_PREFIX_EXEC is ${SQUID_PREFIX_EXEC}"

if [ ! -d "${SQUID_PREFIX_PATH}/${SQUID_PATH}" ]; then
  echo "SQUID path ${SQUID_PREFIX_PATH}/${SQUID_PATH} is not found, aborting"
  exit 1
fi


#CONF


echo "Backuping the current squidGuard.conf config file."

if [ -f "${SQUID_PREFIX_PATH}/${SQUID_CONF_PATH}/squidGuard.conf" ]; then
  cp "${SQUID_PREFIX_PATH}/${SQUID_CONF_PATH}/squidGuard.conf" "${SQUID_PREFIX_PATH}/${SQUID_CONF_PATH}/squidGuard.conf.old"
fi

echo "Copying the new squidGuard.conf file."

if [ -f ${TMP_PATH}/squidGuard.conf ]; then
  cp ${TMP_PATH}/squidGuard.conf "${SQUID_PREFIX_PATH}/${SQUID_CONF_PATH}/squidGuard.conf"
else
  echo "New squidGuard.conf conf files is not found, exiting";
  exit 1
fi


# DB


echo "Backuping the current squidGuard Database."

if [ -d "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}.old" ]; then
  rm -rf "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}.old"
fi

echo "Backuping the current squidGuard Database."

if [ -d "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}" ]; then
  cp -a "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}" "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}.old"
fi

echo "Copying the new squidGuard Database."

if [ -d ${TMP_PATH}/cleanify ]; then
  rm -rf "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}"
  cp -a ${TMP_PATH}/cleanify "${SQUID_PREFIX_PATH}/${SQUID_DB_PATH}"
else
  echo "New squidGuard DB is not found, exiting";
  exit 1
fi

echo "Now reloading configuration !"
${SQUID_PREFIX_EXEC} /usr/sbin/update-squidguard
echo $?
