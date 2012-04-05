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
POWERDNS_PATH=${powerdns_path}

echo "TMP_PATH is ${TMP_PATH}"
echo "POWERDNS_PATH is ${POWERDNS_PATH}"

if [ ! -d ${POWERDNS_PATH} ]; then
  echo "POWERDNS path ${POWERDNS_PATH} is not found, aborting."
  exit 1
fi

bindconf=${TMP_PATH}/named.conf.block
db=${POWERDNS_PATH}/sqlite/db.sqlite3

# and if file is not '0'
if [[ -r $db ]]; then
    echo `date +'%Y-%m-%d %H:%M:%S (%s)'` "Backuping the current config file"
    # If not powerDNS will be serving an empty conf...
    cp $db ${db}.new
else
    echo `date +'%Y-%m-%d %H:%M:%S (%s)'` "Must use an existing sqlite3 database with schema setup."
    if [ -r /usr/share/doc/pdns-backend-sqlite3/examples/sqlite3.sql ]; then
       echo "Setiing-up the sqlite3 database with schema."
       cat /usr/share/doc/pdns-backend-sqlite3/examples/sqlite3.sql | sqlite3 ${db}.new
    else
        echo "Could not found the sqlite3 schema database file."
        exit 1;
    fi
fi


echo `date +'%Y-%m-%d %H:%M:%S (%s)'` "Cleaning the sqlite database content."
sqlite3 ${db}.new 'delete from records'

echo `date +'%Y-%m-%d %H:%M:%S (%s)'` "Injecting the data in the sqlite database."
zone2sql --named-conf=$bindconf 2>/dev/null | sqlite3 ${db}.new

cp $db ${db}.old
cp ${db}.new $db

echo `date +'%Y-%m-%d %H:%M:%S (%s)'` "Now reloading configuration !"
/etc/init.d/pdns reload

sleep 2
/etc/init.d/pdns status 
 
