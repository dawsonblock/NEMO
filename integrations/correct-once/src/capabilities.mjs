// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { CapabilityError } from './errors.mjs';

export const REFERENCE_CAPABILITIES = Object.freeze([
  {
    id: 'nemo.pure.json_digest',
    capabilityClass: 'pure',
    executionClass: 'pure',
    operation: 'pure.digest',
    description: 'Digest a canonical JSON document.',
    schema: { type: 'object', required: ['document'] },
  },
  {
    id: 'nemo.read.file_snapshot',
    capabilityClass: 'read',
    executionClass: 'read',
    operation: 'read.file_snapshot',
    description: 'Read a bounded file beneath an approved root.',
    schema: { type: 'object', required: ['relativePath'] },
  },
  {
    id: 'nemo.mutation.file_write_atomic',
    capabilityClass: 'mutation',
    executionClass: 'mutation',
    operation: 'mutation.file_write_atomic',
    description: 'Write a file with an atomic replacement and optional predecessor digest.',
    schema: { type: 'object', required: ['relativePath', 'content'] },
  },
  {
    id: 'nemo.mutation.file_delete_approved',
    capabilityClass: 'mutation',
    executionClass: 'critical',
    operation: 'mutation.file_delete_approved',
    approvalRequired: true,
    server: 'local-filesystem',
    tool: 'delete',
    description: 'Delete a file after scoped Correct-Once approval.',
    schema: { type: 'object', required: ['relativePath', 'expectedDigest', 'reason'] },
  },
]);

function digestBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safePath(root, relativePath) {
  if (typeof relativePath !== 'string' || isAbsolute(relativePath))
    throw new CapabilityError('PATH_REJECTED', 'relativePath must be relative');
  const resolvedRoot = resolve(root);
  const target = resolve(resolvedRoot, relativePath);
  if (relative(resolvedRoot, target).startsWith('..'))
    throw new CapabilityError('PATH_REJECTED', 'path escapes the approved root');
  return target;
}

async function ensureRegularFile(path) {
  const info = await lstat(path);
  if (info.isSymbolicLink()) throw new CapabilityError('PATH_REJECTED', 'symbolic links are not allowed');
  if (!info.isFile()) throw new CapabilityError('PATH_REJECTED', 'target is not a regular file');
  return info;
}

async function ensureNoSymlinkComponents(root, target) {
  const relativeTarget = relative(root, target);
  const components = relativeTarget ? relativeTarget.split('/') : [];
  let current = root;
  for (const component of components) {
    current = resolve(current, component);
    try {
      const info = await lstat(current);
      if (info.isSymbolicLink()) throw new CapabilityError('PATH_REJECTED', 'symbolic links are not allowed');
    } catch (error) {
      if (error?.code === 'ENOENT') break;
      throw error;
    }
  }
}

export function createReferenceHandlers({ root }) {
  if (!root) throw new TypeError('root is required');
  return new Map([
    [
      'nemo.pure.json_digest',
      async ({ document }) => {
        const { canonicalize } = await import('./canonical.mjs');
        return { digest: digestBytes(Buffer.from(canonicalize(document), 'utf8')) };
      },
    ],
    [
      'nemo.read.file_snapshot',
      async ({ relativePath, maxBytes = 1024 * 1024 }) => {
        const target = safePath(root, relativePath);
        await ensureNoSymlinkComponents(resolve(root), target);
        const info = await ensureRegularFile(target);
        if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || info.size > maxBytes)
          throw new CapabilityError('READ_LIMIT', 'file exceeds maxBytes');
        const content = await readFile(target);
        return { relativePath, bytes: content.length, digest: digestBytes(content), content: content.toString('utf8') };
      },
    ],
    [
      'nemo.mutation.file_write_atomic',
      async ({ relativePath, content, expectedDigest }) => {
        const target = safePath(root, relativePath);
        await ensureNoSymlinkComponents(resolve(root), target);
        if (expectedDigest) {
          const current = await readFile(target).catch((error) => {
            if (error.code === 'ENOENT') return null;
            throw error;
          });
          if (!current || digestBytes(current) !== expectedDigest)
            throw new CapabilityError('PRECONDITION_FAILED', 'predecessor digest does not match');
        }
        const bytes = Buffer.from(String(content), 'utf8');
        await mkdir(dirname(target), { recursive: true });
        const temporary = `${target}.nemo-${randomUUID()}.tmp`;
        await writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
        await rename(temporary, target);
        return { relativePath, bytes: bytes.length, digest: digestBytes(bytes) };
      },
    ],
    [
      'nemo.mutation.file_delete_approved',
      async ({ relativePath, expectedDigest }) => {
        const target = safePath(root, relativePath);
        await ensureNoSymlinkComponents(resolve(root), target);
        const current = await readFile(target).catch((error) => {
          if (error.code === 'ENOENT') return null;
          throw error;
        });
        if (!current || digestBytes(current) !== expectedDigest)
          throw new CapabilityError('PRECONDITION_FAILED', 'delete predecessor digest does not match');
        await unlink(target);
        return { relativePath, deletedDigest: expectedDigest };
      },
    ],
  ]);
}
