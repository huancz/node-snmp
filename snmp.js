
var assert = require('assert');
var binding = require('snmp_binding');
var util = require('util');

var hex = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F' ];

function interpret_oid(aOid) {
  if (typeof(aOid) == "string") {
    return binding.parse_oid(aOid);
  } else if (aOid instanceof Array) {
    return aOid;
  } else if (aOid instanceof binding.cSnmpValue) {
    return aOid.asArray();
  } else {
    assert.ok(false, "unsupported aOid data type " + typeof(aOid) + ":" + util.inspect(aOid));
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
  } else if (typeof(v) == "number") {
    return ("" + v);
  } else if (v instanceof Array) {
    return v.join(",");
  } else if (v === null) {
    return "<NULL>";
  } else {
    assert.ok(false, "internal error: unknown value type received from binding: " + v + " -> " + util.inspect(v));
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

// function oid_compare_base(aLeft, aRight) {{{
function oid_compare_base(aLeft, aRight) {
  var left = interpret_oid(aLeft);
  var right = interpret_oid(aRight);

  // console.log("compare base - L: ", left);
  // console.log("compare base - R: ", right);

  var end = Math.min(left.length, right.length);
  var i;
  for (i = 0; i < end; ++i) {
    if (left[i] < right[i]) {
      return -1;
    } else if (left[i] > right[i]) {
      return 1;
    }
  }
  return 0;
}
// }}}
exports.oid_compare_base = oid_compare_base;

// lexicographicaly compare left and right value, result is same as for strcmp
// (-1 if left sorts before right, 0 for equality and 1...)
// function oid_compare(aLeft, aRight) {{{
function oid_compare(aLeft, aRight) {
  var left = interpret_oid(aLeft);
  var right = interpret_oid(aRight);

  var i = oid_compare_base(left, right);
  if (i != 0) {
    return i;
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
exports.oid_compare = oid_compare;

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
  if (aCallback) {
    assert.ok(aCallback instanceof Function, "callback must be a function");
  }

  var oid = interpret_oid(aOid);
  var that = this;

  function verifyNextResult(aReqOid, aReplyOid) {
    // reply to GET_NEXT must be next lexicographically greater row... but some
    // implementations don't follow this  and sometimes return EQUAL_OR_GREATER
    // row => endless cycle. We break it here.
    if (oid_compare(aReqOid, aReplyOid) >= 0) {
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
      that.lastResult = null;
      that.lastError = "broken peer implementation";
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
      console.log("broken implementation: ", oid, interpret_oid(aData[0].oid));
      aCallback("broken peer implementation", null);
      console.log([oid, aData[0].oid]);
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
// conn.prototype.getNextSubtree = function(aOid, aBase, aCallback) {{{
conn.prototype.getNextSubtree = function(aOid, aBase, aCallback) {
  if (aCallback) {
    assert.ok(aCallback instanceof Function, "callback must be a function");
  }
  var base = interpret_oid(aBase);

  function async_callback(aError, aData) {
    if (aError) {
      aCallback(aError, aData);
      return;
    }
    if (oid_compare_base(aData[0].oid, base) != 0) {
      aCallback("end of subtree", null);
    } else {
      aCallback(aError, aData);
    }
  }

  if (aCallback) {
    return this.getNext(aOid, async_callback);
  } else {
    this.getNext(base);
    if (this.lastError) {
      return false;
    }
    if (oid_compare_base(this.lastResult[0].oid, base) != 0) {
      this.lastError = "end of subtree";
      return false;
    }
    return true;
  }
}
// }}}

// conn.prototype.getCompleteSubtree = function(aOid, aCallback) {{{
conn.prototype.getCompleteSubtree = function(aOid, aCallback) {
  // TODO: great opportunity for GET_BULK. IF we support v2 protocol, and the
  // connection is v2...

  // no sync version available for now
  // if (aCallback) {
    assert.ok(aCallback instanceof Function, "callback must be a function");
  // }

  var that = this;
  var results = [];

  function get_subtree_callback(aError, aData) {
    if (aError) {
      aCallback(results);
    } else {
      results.push(aData[0]);
      that.getNextSubtree(aData[0].oid, aOid, get_subtree_callback);
    }
  }

  this.getNextSubtree(aOid, aOid, get_subtree_callback);
}
// }}}

// vim: ts=2 sw=2 et
