// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createReferenceHandlers, REFERENCE_CAPABILITIES } from '../src/capabilities.mjs';

test('reference capabilities expose the four planned routes', () => {
  assert.deepEqual(
    REFERENCE_CAPABILITIES.map((item) => item.id),
    [
      'nemo.pure.json_digest',
      'nemo.read.file_snapshot',
      'nemo.mutation.file_write_atomic',
      'nemo.mutation.file_delete_approved',
    ],
  );
  assert.equal(REFERENCE_CAPABILITIES[3].executionClass, 'critical');
});

test('reference handlers read and atomically mutate only the approved root', async () => {
  const root = await mkdtemp(join(tmpdir(), 'nemo-correct-once-'));
  try {
    const handlers = createReferenceHandlers({ root });
    const digest = await handlers.get('nemo.pure.json_digest')({ document: { b: 2, a: 1 } });
    assert.match(digest.digest, /^[0-9a-f]{64}$/);
    const write = await handlers.get('nemo.mutation.file_write_atomic')({
      relativePath: 'nested/value.txt',
      content: 'hello',
    });
    const read = await handlers.get('nemo.read.file_snapshot')({ relativePath: 'nested/value.txt' });
    assert.equal(read.digest, write.digest);
    assert.equal(read.content, 'hello');
    await assert.rejects(() => handlers.get('nemo.read.file_snapshot')({ relativePath: '../outside.txt' }), /escapes/);
    await writeFile(join(root, 'nested', 'value.txt'), 'hello');
    const deleted = await handlers.get('nemo.mutation.file_delete_approved')({
      relativePath: 'nested/value.txt',
      expectedDigest: write.digest,
      reason: 'test',
    });
    assert.equal(deleted.deletedDigest, write.digest);
    await assert.rejects(() => readFile(join(root, 'nested', 'value.txt')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('reference handlers reject symlink components, including parent directories', async () => {
  const root = await mkdtemp(join(tmpdir(), 'nemo-correct-once-links-'));
  const outside = await mkdtemp(join(tmpdir(), 'nemo-correct-once-outside-'));
  try {
    await writeFile(join(outside, 'secret.txt'), 'secret');
    await symlink(outside, join(root, 'linked'));
    const handlers = createReferenceHandlers({ root });
    await assert.rejects(
      () => handlers.get('nemo.read.file_snapshot')({ relativePath: 'linked/secret.txt' }),
      /symbolic links/,
    );
    await assert.rejects(
      () => handlers.get('nemo.mutation.file_write_atomic')({ relativePath: 'linked/new.txt', content: 'nope' }),
      /symbolic links/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
