#!/bin/bash

# from https://ajdiaz.wordpress.com/2008/02/09/bash-ini-parser/
cfg.parser ()
{
    local IFS
    ini="$(<$1)"                # read the file
    ini="${ini//[/\[}"          # escape [
    ini="${ini//]/\]}"          # escape ]
    IFS=$'\n' && ini=( ${ini} ) # convert to line-array
    ini=( ${ini[*]//;*/} )      # remove comments with ;
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
BIND_PATH=${bind_path}

echo "TMP_PATH is ${TMP_PATH}"
echo "BIND_PATH is ${BIND_PATH}"

BIND_OPT=`grep OPTIONS /etc/default/bind9 | sed -e 's/^.*=//' -e 's/\"//g'`

if [ ! -d ${BIND_PATH} ]; then
  echo "BIND path ${BIND_PATH} is not found, aborting"
  exit 1
fi

echo "Backuping the current config file"

if [ -f ${BIND_PATH}/named.conf.block ]; then
  cp ${BIND_PATH}/named.conf.block ${BIND_PATH}/named.conf.block.old
  cp ${BIND_PATH}/blockeddomain.hosts ${BIND_PATH}/blockeddomain.hosts.old 
fi

echo "Copying the new file"

if [ -f ${TMP_PATH}/named.conf.block ]; then
  cp ${TMP_PATH}/named.conf.block ${BIND_PATH}/named.conf.block
  cp ${TMP_PATH}/blockeddomain.hosts ${BIND_PATH}/blockeddomain.hosts
else
  echo "New file blacklist is not found, exiting";
  exit 1
fi

echo "Checking named.conf file :"
CheckOUT=`/usr/sbin/named-checkconf -z ${BIND_PATH}/named.conf 2>&1 > /dev/null`
CheckRTN=$?

# dumb '_'

#echo "CheckOUT is echo ${CheckOUT}"

#UCheckErr=`echo $CheckOUT | wc -l`
#echo "Number of error is '${UCheckErr}'."

CheckErr=`echo $CheckOUT | grep -v '^_default/.*/IN: bad owner name (check-names)$' | wc -l`
#echo "Number of error is '${CheckErr}'."
#echo "Rtn is ${CheckRTN}"

if [ $CheckRTN -ne 0 -a ${CheckErr} -ne 0 ]; then
  echo -e "\t"'\E[30;41m'"   NOK   \033[0m";
  echo "The checkConf failed."
  echo $CheckOUT 

  echo "Rolling back file conf"
  cp ${BIND_PATH}/named.conf.block.old ${BIND_PATH}/named.conf.block
  cp ${BIND_PATH}/blockeddomain.hosts.old ${BIND_PATH}/blockeddomain.hosts
  exit 1
else 
  echo -e "\t"'\E[30;42m'"   OK    \033[0m";
  echo $CheckOUT
fi

echo "Now reloading configuration !"
/etc/init.d/bind9 reload
sleep 2
/etc/init.d/bind9 status 
 
