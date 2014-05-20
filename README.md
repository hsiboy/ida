ida
===

Description
-----------

IDSA is part of my research project. I am investigating how 
a log or audit system can be extended into a reference monitor
and IDS.

Officially IDSA is a stateful, extensible and voluntary
userland reference monitor with logging and extended response 
capabilities. 

But you can think of it as a syslogd with attitude, or maybe
an application firewall. See doc/BLURB for some of its 
features.

Installation
------------

To install read doc/INSTALL. You need to run Linux >= 2.2.x

Installation instructions for the impatient:

  ./configure ; make install

Documentation
-------------

Manual pages are available for most subsystems. Type
the below to see the index:

  man idsa

License
-------

The file include/idsa_schemes.h is released under a BSD license
The remaining files in include/ and lib/ are released under the LGPL
The rest of the system is released under the GNU GPL. 

See doc/GPL and doc/LGPL.

Development
-----------

IDSA has just emerged from a partial rewrite and is barely
alpha software. It has not been audited. See doc/WARNING
before trusting it.

IDSA is far from being complete. If you would like to help 
look at doc/TODO.

There is an IDSA mailing list. To subscribe send 
a message to idsa-list@jade.cs.uct.ac.za with the word
subscribe in the subject. The homepage of idsa is
http://jade.cs.uct.ac.za/idsa/

Marc
marc@jade.cs.uct.ac.za 
Cape Town, July 2000
