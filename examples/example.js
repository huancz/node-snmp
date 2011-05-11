var conn = new (require('snmp').Connection)("localhost", "public");

function snmpCallback(aExample, aError, aData) {
  if (aError) {
    console.log(aExample + ": error occured - " + aError);
    return;
  }
  var i = aData.length - 1;
  for (; i >= 0; --i) {
    var d = aData[i];
    console.log(aExample + ": " + d.oid.toArray().join(".") + ": "
	+ d.value.toString());
  }
}

// error - OID doesn't match any single value (only a tree node)
conn.Get(".1.3.6.1.2.1.1.1", snmpCallback.bind(undefined, "example 1"));

// various ways to ask for sysDescr.0
conn.Get(".1.3.6.1.2.1.1.1.0", snmpCallback.bind(undefined, "example 2"));
conn.Get("sysDescr.0", snmpCallback.bind(undefined, "example 3"));
conn.Get([[1,3,6,1,2,1,1,1,0], [1,3,6,1,2,1,1,1,0] ],
    snmpCallback.bind(undefined, "example 4"));

// getNext - returns sysDescr.0 too
conn.GetNext([0], snmpCallback.bind(undefined, "example 5"));

// query all network interface names
conn.GetSubtree("ifDescr", snmpCallback.bind(undefined, "example 6"));

