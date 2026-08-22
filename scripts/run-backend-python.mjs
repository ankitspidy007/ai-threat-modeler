import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const backend = resolve(root, 'backend');
const localPython = process.platform === 'win32'
    ? resolve(backend, '.venv', 'Scripts', 'python.exe')
    : resolve(backend, '.venv', 'bin', 'python');

const candidates = [
    process.env.AEGIS_PYTHON,
    localPython,
    'python3',
    'python',
].filter(Boolean);

for (const executable of candidates) {
    if (executable.includes('/') || executable.includes('\\')) {
        if (!existsSync(executable)) continue;
    }

    const result = spawnSync(executable, process.argv.slice(2), {
        cwd: backend,
        stdio: 'inherit',
        shell: false,
    });
    if (result.error?.code === 'ENOENT') continue;
    if (result.error) {
        console.error(`Unable to start ${executable}: ${result.error.message}`);
        process.exit(1);
    }
    process.exit(result.status ?? 1);
}

console.error('Python was not found. Create backend/.venv or set AEGIS_PYTHON.');
process.exit(1);
