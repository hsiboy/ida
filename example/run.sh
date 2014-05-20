#!/bin/sh

# to locate the library in case it has not been installed
export LD_LIBRARY_PATH=../lib

# normally applications connect to /var/run/idsa, override
# this (only works for applications which set the IDSA_F_ENV
# flag) in case a real idsad is running
export IDSA_SOCKET=/dev/null

# use a static configuration file (normally in 
# /etc/idsa.d/"servicename") 
export IDSA_CONFIG=`pwd`/idsa.d

# run the application
exec ./simple-example

# if idsa is installed and idsad is running, none of the
# above environment variables are needed, and the rules
# can go into /etc/idsad.conf
