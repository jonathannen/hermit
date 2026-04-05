"use strict";

(function(current) {
  const core = Deno.core;
  const log = core.ops.op_log;

  // Capture builtins before lockdown
  const _Array = Array;
  const _Boolean = Boolean;
  const _Error = Error;
  const _EvalError = EvalError;
  const _JSON = JSON;
  const _Map = Map;
  const _Number = Number;
  const _Object = Object;
  const _Promise = Promise;
  const _RangeError = RangeError;
  const _ReferenceError = ReferenceError;
  const _Set = Set;
  const _String = String;
  const _SyntaxError = SyntaxError;
  const _TypeError = TypeError;
  const _URIError = URIError;
  const _defineProperty = Object.defineProperty;
  const _freeze = Object.freeze;

  // Poison Function constructor
  const poisonConstructor = () => {
    throw new _Error("Function constructor is disabled");
  };
  poisonConstructor.prototype = {};
  _freeze(poisonConstructor.prototype);
  _freeze(poisonConstructor);

  const syncFunc = function() {};
  const asyncFunc = async function() {};
  const genFunc = function* () {};
  const asyncGenFunc = async function* () {};

  _defineProperty(Object.getPrototypeOf(syncFunc), "constructor", {
    configurable: false, value: poisonConstructor, writable: false
  });
  _defineProperty(Object.getPrototypeOf(asyncFunc), "constructor", {
    configurable: false, value: poisonConstructor, writable: false
  });
  _defineProperty(Object.getPrototypeOf(genFunc), "constructor", {
    configurable: false, value: poisonConstructor, writable: false
  });
  _defineProperty(Object.getPrototypeOf(asyncGenFunc), "constructor", {
    configurable: false, value: poisonConstructor, writable: false
  });

  // Disable eval at JS level (belt-and-suspenders with V8 flag)
  _defineProperty(current, "eval", {
    configurable: false,
    value: () => { throw new _Error("eval is disabled"); },
    writable: false
  });

  // Freeze prototypes (all Error subclasses included to prevent prototype pollution)
  _freeze(_Array.prototype);
  _freeze(_Boolean.prototype);
  _freeze(_Error.prototype);
  _freeze(_EvalError.prototype);
  _freeze(_Map.prototype);
  _freeze(_Number.prototype);
  _freeze(_Object.prototype);
  _freeze(_Promise.prototype);
  _freeze(_RangeError.prototype);
  _freeze(_ReferenceError.prototype);
  _freeze(_Set.prototype);
  _freeze(_String.prototype);
  _freeze(_SyntaxError.prototype);
  _freeze(_TypeError.prototype);
  _freeze(_URIError.prototype);
  _freeze(Object.getPrototypeOf(syncFunc));
  _freeze(Object.getPrototypeOf(asyncFunc));
  _freeze(Object.getPrototypeOf(genFunc));
  _freeze(Object.getPrototypeOf(asyncGenFunc));

  // Freeze prototypes reachable through literals/builtins despite constructor deletion.
  // Without these, sandbox code can pollute prototypes across eval blocks.
  _freeze(RegExp.prototype);                                         // /foo/.constructor.prototype
  _freeze(Symbol.prototype);                                         // recoverable via getOwnPropertySymbols
  const _arrIter = [].values();
  const _ArrayIteratorProto = Object.getPrototypeOf(_arrIter);
  const _IteratorProto = Object.getPrototypeOf(_ArrayIteratorProto);
  _freeze(_ArrayIteratorProto);                                      // [].values().__proto__
  _freeze(_IteratorProto);                                           // IteratorPrototype (parent of all iterators)
  _freeze(Object.getPrototypeOf(new _Map().values()));               // MapIteratorPrototype
  _freeze(Object.getPrototypeOf(new _Set().values()));               // SetIteratorPrototype
  _freeze(Object.getPrototypeOf(""[Symbol.iterator]()));             // StringIteratorPrototype

  // Delete dangerous globals
  delete current.Deno;
  delete current.Date;
  delete current.Math;
  delete current.crypto;
  delete current.Reflect;
  delete current.Proxy;
  delete current.WeakRef;
  delete current.FinalizationRegistry;
  delete current.SharedArrayBuffer;
  delete current.Atomics;
  delete current.ArrayBuffer;
  delete current.DataView;
  delete current.Int8Array;
  delete current.Uint8Array;
  delete current.Uint8ClampedArray;
  delete current.Int16Array;
  delete current.Uint16Array;
  delete current.Int32Array;
  delete current.Uint32Array;
  delete current.Float32Array;
  delete current.Float64Array;
  delete current.BigInt64Array;
  delete current.BigUint64Array;
  delete current.Map;
  delete current.Set;
  delete current.WeakMap;
  delete current.WeakSet;
  delete current.Symbol;
  delete current.RegExp;
  delete current.BigInt;
  delete current.Intl;
  delete current.console;
  delete current.queueMicrotask;

  // Clear any remaining enumerable properties
  for (const key of _Object.keys(current)) {
    if (key !== "globalThis") {
      delete current[key];
    }
  }

  // Restore safe builtins
  current.Array = _Array;
  current.Boolean = _Boolean;
  current.Error = _Error;
  current.JSON = _JSON;
  current.Map = _Map;
  current.Number = _Number;
  current.Object = _Object;
  current.Promise = _Promise;
  current.RangeError = _RangeError;
  current.Set = _Set;
  current.String = _String;
  current.TypeError = _TypeError;

  // Install console.log (the only output primitive)
  const console = _freeze({
    log: (...args) => log(args.map(_String).join(" "))
  });
  _defineProperty(current, "console", {
    value: console, writable: false, configurable: false
  });

  _freeze(current);
})(globalThis);
