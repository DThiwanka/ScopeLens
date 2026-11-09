/**
 * ScopeLens Automated Test Suite - Assertion Helpers
 */

export function assert(condition, message = 'Assertion failed') {
  if (!condition) {
    throw new Error(message);
  }
}

export function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected [${expected}] but received [${actual}]`);
  }
}

export function assertTrue(condition, message) {
  assertEqual(Boolean(condition), true, message || 'Expected true');
}

export function assertFalse(condition, message) {
  assertEqual(Boolean(condition), false, message || 'Expected false');
}

export function assertThrows(fn, message) {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  if (!threw) {
    throw new Error(message || 'Expected function to throw an error');
  }
}
