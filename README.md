# xxhash-wasm-vn
[![npm](https://img.shields.io/npm/v/xxhash-wasm-vn)](https://www.npmjs.com/package/xxhash-wasm-vn)

## Node.js

```js
const { xh32, xxh64, xxh3_64, xxh3_128 } = require('xxhash-wasm-vn/nodejs');

```

## Browser

```js
import init, { xxh32, xxh64, xxh3_64, xxh3_128 } from 'xxhash-wasm-vn/web';

await init();

// Classic XXHash
const data = new TextEncoder().encode("hello world");

console.log("xxh32: ", xxh32(data, undefined));
console.log("xxh64: ", xxh64(data, undefined));
console.log("xxh3 (64): ", xxh3_64(data, undefined));
console.log("xxh3 (128): ", xxh3_128(data, undefined));
```
