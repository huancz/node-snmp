
var binding = require('snmp_binding');

var hex = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F' ];

function interpret_oid(aOid) {
  if (typeof(aOid) == "string") {
    return binding.parse_oid(aOid);
  } else if (aOid instanceof Array) {
    return aOid;
  } else if (aOid instanceof binding.cSnmpValue) {
    return aOid.asAray();
  } else {
    throw "unsupported aOid data type " + typeof(aOid);
  }
}

// binding.cSnmpValue.prototype.asString = function() {{{
binding.cSnmpValue.prototype.asString = function() {
  var v = this.GetData();

  if (v instanceof Buffer) {
    // Similar  to  heuristics  in  net-snmp snprint_octet_str.  We  can't  use
    // exception,  Buffer.toString('utf8') appears  to  NOT  throw when  string
    // contains invalid characters.
    //
    // We could do better with hints about data type from MIB... TODO?
    var printable = true;
    for(var i = 0; i < v.length; ++i) {
      if (v[i] > 127) {
        printable = false;
        break;
      }
    }
    if (printable) {
      return v.toString('ascii');
    } else {
      var output = [];
      for (var i = 0; i < v.length; ++i) {
        output.push(hex[v[i] >> 4] + hex[v[i] & 15] + " ");
      }
      return output.join("");
    }
  } else if (v instanceof Number) {
    return ("" + v);
  } else if (v instanceof Array) {
    return v.join(",");
  } else if (v === null) {
    return "<NULL>";
  } else {
    throw "internal error: unknown value type received from binding";
  }
}
// }}}

// binding.cSnmpValue.prototype.asArray = function() {{{
binding.cSnmpValue.prototype.asArray = function() {
  var v = this.GetData();

  if (v instanceof Buffer) {
    // XXX: Buffer is close enough to Array to not worry about something more
    // elaborate - clients expecting array (IP address, MAC, ...) should
    // query GetData anyway.
    return v;
  } else if (v instanceof Number) {
    return [ v ];
  } else if (v instanceof Array) {
    return v;
  } else if (v === null) {
    return [ v ];
  } else {
    throw "internal error: unknown value type received from binding";
  }
}
// }}}

// lexicographicaly compare left and right value, result is same as for strcmp
// (-1 if left sorts before right, 0 for equality and 1...)
// function compare_oid(aLeft, aRight) {{{
function compare_oid(aLeft, aRight) {
  left = interpret_oid(aLeft);
  right = interpret_oid(aRight);

  var end = Math.min(left.length, right.length);
  var i;
  for (i = 0; i < end; ++i) {
    if (left[i] < right[i]) {
      return -1;
    } else if (left[i] > right[i]) {
      return 1;
    }
  }
  // common parts are equal - if right is longer, it sorts as greater
  if (left.length < right.length) {
    return -1;
  } else if (left.length > right.length) {
    return 1;
  }
  return 0;
}
// }}}
exports.compare_oid = compare_oid;

/**
 * Parse dotted oid format to array of integers.
 */
exports.read_objid = binding.read_objid;
/**
 * Parse any recongnizable oid format (including MIB translation) to array
 * of integers.
 */
exports.parse_oid = binding.parse_oid;





var conn = exports.cSnmpConnection = function cSnmpConnection(aHost, aCredentials) {
  this.worker_ = new (binding.cSnmpSession)(aHost, aCredentials);
}

conn.prototype.get = function(aOid, aCalback) {
  if (aCallback) {
    return this.worker_.get(aOid, aCallback, false);
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
      this.lastResult = result_val;
      return true;
    }
  }
}

/**
 * Direct  mapping for  GET_NEXT  snmp  operation -  returns  contents of  next
 * lexicographically greater MIB variable, without restrictions. Sync behaviour
 * when  callback  is  not  specified  and binding  module  was  compiled  with
 * -DEV_MULTIPLICITY=1, otherwise it behaves asynchronously.
 *
 * Sync version  returns true if query  succeeded, false when not.  Results are
 * passed to caller in session.lastResult and session.lastError.
 *
 * Async  version just  calls callback  with (aError,  aData) when  response is
 * ready.
 *
 * Data is passed as  array of objects - we could  support multi-oid queries in
 * future. Each member of the array will have 'oid' and 'value' properties.
 */
// conn.prototype.getNext = function(aOid, aCallback) {{{
conn.prototype.getNext = function(aOid, aCallback) {

  var oid = interpret_oid(aOid);
  var that = this;
  var sync_err = false;

  function verifyNextResult(aReqOid, aReplyOid) {
    // reply to GET_NEXT must be next lexicographically greater row... but some
    // implementations don't follow this  and sometimes return EQUAL_OR_GREATER
    // row => endless cycle. We break it here.
    if (compare_oid <= 0) {
      return false;
    }
    return true;
  }

  function sync_callback(aError, aData) {
    if (aError) {
      sync_err = true;
      that.lastResult = null;
      that.lastError = aError;
      return;
    }
    if (!verifyNextResult(oid, aData[0].oid)) {
      that.lastError = "broken peer implementation";
      that.lastResult = null;
      return;
    }
    that.lastResult = aData;
    that.lastError = null;
  }

  function async_callback(aError, aData) {
    if (aError) {
      aCallback(aError, null);
      return;
    }
    // XXX: this won't work for multi-oid queries
    if (!verifyNextResult(oid, aData[0].oid)) {
      aCallback("broken peer implementation", null);
      return;
    }
    aCallback(false, aData);
  }

  if (aCallback) {
    return this.worker_.getNext(oid, async_callback, false);
  } else {
    this.worker_.getNext(oid, sync_callback, true);
    return !this.lastError;
  }
}
// }}}

/**
 * Wrapper for getNext, restricted to subtree queries.
 */
conn.prototype.getNextSubtree = function(aOid, aCallback) {
  var oid = interpret_oid(aOid);

  if (aCallback) {
  } else {
  }
}

// vim: ts=2 sw=2 et
