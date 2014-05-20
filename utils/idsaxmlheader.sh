#!/bin/sh
#
# add a XML simple header to a log file. 
# Usage : idsaxmlheader < /var/log/idsa/logfile > logfile.xml
#
echo -e "<?xml version=\"1.0\"?>\n<log>"
cat
echo "</log>"
