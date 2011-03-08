
// legacy wrapper... don't ask, and try to not use

var binding = require('snmp_binding');



var ValueWrapper = function(aValue) {
	this.value_ = aValue;
	// pType, pValue - not used
}

ValueWrapper.prototype.asString = function() {

}

ValueWrapper.prototype.asArray = function() {
}




var conn = exports.cSnmpConnection = function cSnmpConnection(aHost, aCredentials) {
  this.worker_ = new (binding.cSnmpSession)(aHost, aCredentials);
}

conn.prototype.getNext = function(aOid, aCallback) {
  if (aCallback) {
    return this.worker_.getNext(aOid, aCallback, false);
  } else {
    var result_err;
    var result_val;

    function callback(aError, aData) {
      result_err = aError;
      result_val = aData;
    }

    this.worker_.getNext(aOid, callback, true);

    if (result_err) {
      return false;
    } else {
      if (result_val.length() > 1) {
        throw "multi-value queries are not supported in legacy binding");
      }
      this.lastValue = new ValueWrapper(result_val[0].value);
      this.lastOid = new ValueWrapper(result_val[0].oid);
      return true;
    }
  }
}

// vim: ts=2 sw=2 et
