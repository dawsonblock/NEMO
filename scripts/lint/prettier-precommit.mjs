// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..', '..');
const nodePackageDir = path.join(repoRoot, 'crates', 'node');
const npmExecutable = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const args = process.argv
  .slice(2)
  .filter((arg) => arg.length > 0)
  .map((arg) => {
    const repoPath = path.resolve(repoRoot, arg);
    if (fs.existsSync(repoPath)) {
      return path.relative(repoRoot, repoPath);
    }

    const packagePath = path.resolve(nodePackageDir, arg);
    if (fs.existsSync(packagePath)) {
      return path.relative(repoRoot, packagePath);
    }

    return arg;
  });

if (args.length === 0) {
  process.exit(0);
}

const result = spawnSync(
  npmExecutable,
  ['--prefix', nodePackageDir, 'exec', '--', 'prettier', '--write', '--check', '--', ...args],
  {
  cwd: repoRoot,
  stdio: 'inherit',
  shell: process.platform === 'win32',
  },
);

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
