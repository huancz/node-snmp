
var assert = require('assert');
var binding = require('./snmp_binding');
var util = require('util');

var hex = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F' ];

function interpret_oid(aOid) {
  if (typeof(aOid) == "string") {
    return binding.parse_oid(aOid);
  } else if (aOid instanceof Array) {
    return aOid;
  } else if (aOid instanceof binding.Value) {
    return aOid.toArray();
  } else {
    assert.ok(false, "unsupported aOid data type " + typeof(aOid) + ":" + util.inspect(aOid));
  }
}

// binding.Value.prototype.asString = function() {{{
binding.Value.prototype.toString = function toString() {
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

// binding.Value.prototype.toArray = function() {{{
binding.Value.prototype.toArray = function() {
  var v = this.GetData();

  if (v instanceof Buffer) {
    var res = [];
    for (var i = 0; i < v.length; ++i) {
      res.push(v[i]);
    }
    return res;
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





var ERR_OTHER = 0;
var ERR_EOF   = 1;
var ERR_CYCLE = 2;

var Error = function(aMessage, aCode) {
  this.message_ = aMessage;
  this.code_ = aCode || ERR_OTHER;
}

Error.prototype.toString = function() {
  return this.message_.toString();
}

Error.prototype.isEof = function() {
  return this.code_ == ERR_EOF;
}







var conn = exports.Connection = function Connection(aHost, aCredentials) {
  this.worker_ = new (binding.Connection)(aHost, aCredentials);
}

conn.prototype.Get = function(aOid, aCallback) {
  var oid = interpret_oid(aOid);
  if (aCallback) {
    return this.worker_.Get(oid, aCallback, false);
  } else {
    var result_err;
    var result_val;

    function callback(aError, aData) {
      result_err = aError;
      result_val = aData;
    }

    this.worker_.Get(oid, callback, true);

    if (result_err) {
      this.lastError = new Error(result_err);
      this.lastResult = null;
      return false;
    } else {
      this.lastResult = result_val;
      this.lastError = null;
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
// conn.prototype.GetNext = function(aOid, aCallback) {{{
conn.prototype.GetNext = function(aOid, aCallback) {
  if (aCallback) {
    assert.ok(aCallback instanceof Function,
        "callback must be a function");
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
      that.lastError = new Error(aError);
      return;
    }
    if (!verifyNextResult(oid, aData[0].oid)) {
      that.lastResult = null;
      that.lastError = new Error("broken peer implementation", ERR_CYCLE, null);
      return;
    }
    that.lastResult = aData;
    that.lastError = null;
  }

  function async_callback(aError, aData) {
    if (aError) {
      aCallback(new Error(aError), null);
      return;
    }
    // XXX: this won't work for multi-oid queries
    if (!verifyNextResult(oid, aData[0].oid)) {
      aCallback(new Error("broken peer implementation", ERR_CYCLE), null);
      console.log([oid, aData[0].oid]);
      return;
    }
    aCallback(false, aData);
  }

  if (aCallback) {
    return this.worker_.GetNext(oid, async_callback, false);
  } else {
    this.worker_.GetNext(oid, sync_callback, true);
    return !this.lastError;
  }
}
// }}}

/**
 * Wrapper for GetNext, restricted to subtree queries.
 */
// conn.prototype.getNextSubtree = function(aOid, aBase, aCallback) {{{
conn.prototype.getNextSubtree = function(aOid, aBase, aCallback) {
  if (aCallback) {
    assert.ok(aCallback instanceof Function, "callback must be a function");
  }
  var base = interpret_oid(aBase);

  function async_callback(aError, aData) {
    if (aError) {
      aCallback(new Error(aError), aData);
      return;
    }
    if (oid_compare_base(aData[0].oid, base) != 0) {
      aCallback(new Error("end of subtree", ERR_EOF), null);
    } else {
      aCallback(null, aData);
    }
  }

  if (aCallback) {
    return this.GetNext(aOid, async_callback);
  } else {
    if (!this.GetNext(base)) {
      return false;
    }
    if (oid_compare_base(this.lastResult[0].oid, base) != 0) {
      this.lastError = new Error("end of subtree", ERR_EOF);
      return false;
    }
    return true;
  }
}
// }}}

// conn.prototype.GetSubtree = function(aOid, aCallback) {{{
conn.prototype.GetSubtree = function(aOid, aCallback) {
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
      if (aError.isEof()) {
        aCallback(false, results);
      } else {
        aCallback(aError);
      }
    } else {
      results.push(aData[0]);
      that.getNextSubtree(aData[0].oid, aOid, get_subtree_callback);
    }
  }

  this.getNextSubtree(aOid, aOid, get_subtree_callback);
}
// }}}

// vim: ts=2 sw=2 et
