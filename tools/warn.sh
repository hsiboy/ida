#!/bin/bash

if [ -e /usr/bin/tput ] ; then 
  tput setf 2 2> /dev/null
  tput smso 2> /dev/null
fi

echo "WARNING                    : $*"

if [ -e /usr/bin/tput ] ; then 
  tput sgr0 2> /dev/null 
fi
