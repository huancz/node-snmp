node-snmp
=========

Binding for Net-SNMP library, and simple wrapper  to make life a bit easier.


Features
--------
So far only snmp queries and protocol V1 are supported. It has both synchronous
and asynchronous interface, but the former requires libev compiled with support
for multiple  event loops. As stock  node is by default  compiled without this,
only  asynchronous queries  are usually  available  - unless  you compile  node
binary yourself.


Dependencies
------------
Net-SNMP library - tested with version 5.4.3


Build
-----
1. node-waf configure build
2. copy snmp.js and build/default/snmp_binding.js somewhere where node can find
   them:
   - ~/.node_libraries
   - <your_project>/node_modules/snmp (copy package.json too when using this
     variant)
   see http://nodejs.org/docs/v0.4.7/api/modules.html for details

Eventually, "npm install -g" should do the trick, but I can't seem to get it to
work.


API
---

callbacks  -  all callbacks  are  called  with  fairly standard  (error,  data)
  arguments. 
  
  Error can  be used as boolean  false when query finished  successfully, Error
  object with error description otherwise (convertible to String).
  
  Data is array of  objects with 'value' and 'oid' properties,  both of them of
  type SnmpValue:
  [
    { oid: ..., value: ... },
    { oid: ..., value: ... }
  ]

Value - no public constructor
  - asArray, toString - return some aproximation of contained data, similar to
    what snmpwalk does
  - GetData - return raw data in several possible formats - see asArray for
    details
  - GetType - one of SnmpValue.[VT_NUMBER, VT_TEXT, VT_OID, VT_RAW, VT_NULL]
    Remnant of early design, probably useless, could be removed in the future

Error - no public constructor
  - toString()
  - isEof() - used internally by GetSubtree

Connection(host, community)
  - Get, GetNext - map directly to  corresponding SNMP operations, take OID (in
    any format) or  array of OIDs (only array of  integers format) and callback
    as arguments
  - GetSubtree - use getNext to walk whole subtree of starting OID

free functions in exports:
  - read_objid - parse dotted oid string into array of integers
  - parse_oid - parse any string to array of integers (including MIB
    translation)


Usage example
-------------

var conn = new (require('snmp').cSnmpConnection)("localhost", "public");
conn.get(".1.3.6.1.2.1.1.1", function(aError, aData) { console.log(aData[0].value.toString()); });

see examples/ directory for more complete sample

vim: ts=2 sw=2 et


TODO
----
(in no particular order)
- support for V2 and V3 protocols, bulk queries
- support TRAP operation
- support conversion from OID to MIB symbolic name
- make the package npm-compatible (npm link works, npm install does not)
- find out why example doesn't work when copy/pasted to node cmdline, it must
  be run from file on disk
- cleanup the C++ code (memory leaks in error code paths)


