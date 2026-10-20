import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
const escape=createRequire(import.meta.url)(resolve(process.env.KEEP_CASE_SOURCE,'index.js'));

test('issue20: escaped hyphen constructs and matches under Unicode mode',()=>{
  const escaped=escape('-');
  assert.equal(new RegExp(`^${escaped}$`,'u').test('-'),true);
  assert.equal(new RegExp(`^[${escaped}]$`,'u').test('-'),true);
  assert.equal(new RegExp(`^${escaped}$`,'u').test('x'),false);
});
test('maintainer main: other metacharacter escaping remains exact',()=>{
  assert.equal(escape('\\ ^ $ * + ? . ( ) | { } [ ]'),'\\\\ \\^ \\$ \\* \\+ \\? \\. \\( \\) \\| \\{ \\} \\[ \\]');
});
test('preserved input behavior: empty string and non-string rejection',()=>{
  assert.equal(escape(''),'');
  assert.throws(()=>escape(null),{name:'TypeError',message:'Expected a string'});
});
