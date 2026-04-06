"use strict";

(function (current) {
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
  const _objToString = Object.prototype.toString;

  // Safe serializer that never invokes attacker-controlled code.
  // Handles primitives directly; objects/functions get a static type tag.
  // We avoid Object.prototype.toString because it reads Symbol.toStringTag,
  // which can be a getter on user-created objects.
  function safeString(val) {
    if (val === undefined) return "undefined";
    if (val === null) return "null";
    const t = typeof val;
    if (t === "string") return val;
    if (t === "number" || t === "boolean" || t === "bigint") return "" + val;
    if (t === "function") return "[object Function]";
    // t === "object" -- return static tag to avoid Symbol.toStringTag getters
    return "[object Object]";
  }

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

  const syncFunc = function () {};
  const asyncFunc = async function () {};
  const genFunc = function* () {};
  const asyncGenFunc = async function* () {};

  const _syncFuncProto = _getPrototypeOf(syncFunc);
  const _asyncFuncProto = _getPrototypeOf(asyncFunc);
  const _genFuncProto = _getPrototypeOf(genFunc);
  const _asyncGenFuncProto = _getPrototypeOf(asyncGenFunc);

  _defineProperty(_syncFuncProto, "constructor", {
    configurable: false,
    value: poisonConstructor,
    writable: false,
  });
  _defineProperty(_asyncFuncProto, "constructor", {
    configurable: false,
    value: poisonConstructor,
    writable: false,
  });
  _defineProperty(_genFuncProto, "constructor", {
    configurable: false,
    value: poisonConstructor,
    writable: false,
  });
  _defineProperty(_asyncGenFuncProto, "constructor", {
    configurable: false,
    value: poisonConstructor,
    writable: false,
  });

  // Freeze function prototypes immediately after poisoning to prevent
  // mutation via other references before deepFreeze(current) runs.
  _freeze(_syncFuncProto);
  _freeze(_asyncFuncProto);
  _freeze(_genFuncProto);
  _freeze(_asyncGenFuncProto);

  // Disable eval at JS level (belt-and-suspenders with V8 flag)
  _defineProperty(current, "eval", {
    configurable: false,
    value: () => {
      throw new _Error("eval is disabled");
    },
    writable: false,
  });

  // Freeze prototypes reachable through literals or V8 internal throws but not
  // through the restored allowlist. These survive deletion because literals and
  // catch blocks bypass globalThis.
  // Must happen before deny-by-default deletion so the constructors are accessible.
  _freeze(RegExp.prototype); // /foo/.constructor.prototype
  _freeze(RegExp);
  _freeze(Symbol.prototype); // recoverable via getOwnPropertySymbols
  _freeze(Symbol);
  _freeze(BigInt.prototype); // 42n literal
  _freeze(BigInt);

  // Error subtypes not in the restore list but recoverable at runtime.
  // ReferenceError: undeclared variable access. SyntaxError: JSON.parse.
  // URIError: decodeURI. EvalError: not thrown by V8 but freeze defensively.
  // AggregateError: Promise.any() rejects with it when all inputs reject.
  // InternalError: non-standard, some V8 builds expose it.
  // SuppressedError: explicit resource management (using) - Stage 4, may
  //   appear in future V8 builds.
  deepFreeze(ReferenceError.prototype);
  deepFreeze(SyntaxError.prototype);
  deepFreeze(URIError.prototype);
  deepFreeze(EvalError.prototype);
  if (typeof AggregateError !== "undefined")
    deepFreeze(AggregateError.prototype);
  if (typeof SuppressedError !== "undefined")
    deepFreeze(SuppressedError.prototype);

  // Freeze iterator prototypes (reachable via [].values(), new Map().values(), etc.)
  const _arrIter = [].values();
  const _ArrayIteratorProto = _getPrototypeOf(_arrIter);
  const _IteratorProto = _getPrototypeOf(_ArrayIteratorProto);
  _freeze(_ArrayIteratorProto);
  _freeze(_IteratorProto);
  _freeze(_getPrototypeOf(new _Map().values()));
  _freeze(_getPrototypeOf(new _Set().values()));
  _freeze(_getPrototypeOf(""[Symbol.iterator]()));
  deepFreeze(_getPrototypeOf("".matchAll(/(?:)/g))); // %RegExpStringIteratorPrototype%

  // Freeze generator, async generator, and async function prototypes.
  // These are not reachable from globalThis (created via literal syntax only),
  // so deepFreeze(globalThis) won't reach them. An unfrozen generator prototype
  // allows prototype pollution scoped to all generator instances (hijacking
  // .next/.return/.throw).
  //
  // Each generator function gets its own .prototype, but they all share the
  // same [[Prototype]] chain: genFunc.prototype -> Generator.prototype (shared)
  // -> IteratorPrototype. We must freeze the shared prototypes, not the
  // per-function .prototype objects.
  //
  // Uses genFunc/asyncGenFunc/asyncFunc already defined above for poisoning.
  deepFreeze(_getPrototypeOf(genFunc)); // GeneratorFunction.prototype
  deepFreeze(_getPrototypeOf(genFunc.prototype)); // Generator.prototype (shared)
  deepFreeze(_getPrototypeOf(asyncGenFunc)); // AsyncGeneratorFunction.prototype
  deepFreeze(_getPrototypeOf(asyncGenFunc.prototype)); // AsyncGenerator.prototype (shared)
  deepFreeze(_getPrototypeOf(asyncFunc)); // AsyncFunction.prototype

  // Deny-by-default: delete ALL own properties (string-keyed and symbol-keyed,
  // enumerable and non-enumerable) from globalThis, then restore only the safe
  // allowlist below. This ensures new V8 globals are blocked automatically.
  for (const key of _getOwnPropertyNames(current)) {
    if (key === "globalThis") continue;
    try {
      delete current[key];
    } catch (_) {}
  }
  for (const sym of _getOwnPropertySymbols(current)) {
    try {
      delete current[sym];
    } catch (_) {}
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
    log: (...args) => log(args.map(safeString).join(" ")),
  });
  _defineProperty(current, "console", {
    value: console,
    writable: false,
    configurable: false,
  });

  // Transitively deep-freeze the entire reachable object graph from globalThis.
  // This covers all restored builtins, their prototypes, prototype chains of
  // literals (RegExp, Symbol, iterators), and anything else reachable.
  deepFreeze(current);
})(globalThis);
