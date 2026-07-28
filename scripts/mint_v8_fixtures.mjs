// Mint real V8-serialized bytes via node's v8.serialize (the actual V8
// ValueSerializer). The known JS input value is the oracle (tier-2): the
// deserializer must reproduce it. Run: node scripts/mint_v8_fixtures.mjs
import v8 from 'node:v8';
import { writeFileSync, mkdirSync } from 'node:fs';
mkdirSync('tests/data/v8', { recursive: true });
const cases = {
  'undefined': undefined,
  'null': null,
  'bool_true': true,
  'bool_false': false,
  'int_42': 42,
  'int_neg7': -7,
  'int_zero': 0,
  'double_pi': 3.14,
  'double_neg': -2.5,
  'uint_big': 4000000000,
  'string_ascii': 'hello',
  'string_unicode': 'héllo→世界',
  'string_empty': '',
  'bigint_pos': 123456789012345678901234567890n,
  'bigint_neg': -42n,
  'date': new Date(1600000000000),
  'array_ints': [1, 2, 3],
  'array_mixed': [1, 'two', true, null],
  'array_empty': [],
  'array_holes': (() => { const a = [1]; a[3] = 4; return a; })(),
  'object_simple': { a: 1, b: 'two', c: true },
  'object_empty': {},
  'object_nested': { name: 'x', list: [1, 2, { deep: 'y' }], when: new Date(1600000000000) },
  'map': new Map([['k1', 1], ['k2', 2]]),
  'set': new Set([1, 2, 3]),
  'regexp': /ab+c/gi,
  'number_object': new Number(7),
  'string_object': new String('wrap'),
  'boolean_object': new Boolean(true),
  'arraybuffer': new Uint8Array([1, 2, 3, 4]).buffer,
  'uint8array': new Uint8Array([10, 20, 30]),
  'int32array': new Int32Array([1, -1, 256]),
  'shared_ref': (() => { const o = { v: 1 }; return [o, o]; })(),
};
const manifest = [];
for (const [name, val] of Object.entries(cases)) {
  const buf = v8.serialize(val);
  writeFileSync(`tests/data/v8/${name}.v8`, buf);
  manifest.push(`${name}\t${buf.toString('hex')}`);
}
console.log(manifest.join('\n'));
