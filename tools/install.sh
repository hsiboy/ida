#!/bin/bash
if [ -e /usr/bin/tput ] ; then tput setf 2 2> /dev/null ; fi
echo install $*
if [ -e /usr/bin/tput ] ; then tput setf 1 2> /dev/null ; fi
install $*
code=$?
if [ -e /usr/bin/tput ] ; then tput sgr0 2> /dev/null ; fi
exit $code
