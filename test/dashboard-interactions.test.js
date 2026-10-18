import assert from 'node:assert/strict';
import { test } from 'node:test';
import { constrainWindow } from '../src/dashboard/dashboard.js';

test('dragging either handle preserves order, bounds, and exact selected timestamps', () => {
  assert.deepEqual(constrainWindow(80, 60, 'start', 0, 100), [60, 60]);
  assert.deepEqual(constrainWindow(80, 60, 'end', 0, 100), [80, 80]);
  assert.deepEqual(constrainWindow(-10, 120, 'start', 0, 100), [0, 100]);
  assert.deepEqual(constrainWindow(20, 60, 'start', 0, 100), [20, 60]);
  assert.deepEqual(constrainWindow(100, 100, 'end', 100, 100), [100, 100]);
});
