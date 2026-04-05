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
  const _getOwnPropertyNames = Object.getOwnPropertyNames;
  const _getOwnPropertySymbols = Object.getOwnPropertySymbols;
  const _getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const _getPrototypeOf = Object.getPrototypeOf;
  const _isFrozen = Object.isFrozen;
  const _SetConstructor = Set;
  const _setAdd = Set.prototype.add;
  const _setHas = Set.prototype.has;

  // Transitive deep freeze: walk the entire reachable object graph from `root`
  // and freeze every object/function found. Uses a visited set to handle cycles.
  function deepFreeze(root) {
    const visited = new _SetConstructor();
    const queue = [root];
    while (queue.length > 0) {
      const obj = queue.pop();
      if (obj === null || obj === undefined) continue;
      if (typeof obj !== "object" && typeof obj !== "function") continue;
      if (_setHas.call(visited, obj)) continue;
      _setAdd.call(visited, obj);

      // Freeze this object
      _freeze(obj);

      // Walk own properties (named + symbol)
      const names = _getOwnPropertyNames(obj);
      const syms = _getOwnPropertySymbols(obj);
      for (let i = 0; i < names.length; i++) {
        const desc = _getOwnPropertyDescriptor(obj, names[i]);
        if (desc) {
          if (desc.value !== undefined) queue.push(desc.value);
          if (desc.get) queue.push(desc.get);
          if (desc.set) queue.push(desc.set);
        }
      }
      for (let i = 0; i < syms.length; i++) {
        const desc = _getOwnPropertyDescriptor(obj, syms[i]);
        if (desc) {
          if (desc.value !== undefined) queue.push(desc.value);
          if (desc.get) queue.push(desc.get);
          if (desc.set) queue.push(desc.set);
        }
      }

      // Walk prototype chain
      queue.push(_getPrototypeOf(obj));
    }
  }

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

  // Deny-by-default: delete ALL own properties (enumerable and non-enumerable)
  // from globalThis, then restore only the safe allowlist below. This ensures
  // new V8 globals (e.g. WebAssembly, Iterator) are blocked automatically.
  for (const key of _getOwnPropertyNames(current)) {
    if (key === "globalThis") continue;
    try { delete current[key]; } catch(_) {}
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

  // Transitively deep-freeze the entire reachable object graph from globalThis.
  // This covers all restored builtins, their prototypes, prototype chains of
  // literals (RegExp, Symbol, iterators), and anything else reachable.
  deepFreeze(current);
})(globalThis);
