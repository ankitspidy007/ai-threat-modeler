/**
 * Parse a generated Mermaid diagram the way the browser will, so a syntax
 * error is found here rather than in front of an audience.
 *
 * Usage: node scripts/check-diagram-syntax.mjs <file.mmd|directory> [more...]
 *
 * Inputs are resolved here rather than by the shell, because the check has to
 * behave the same way on the developer's machine as it does in CI.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;
if (!globalThis.navigator) {
    Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator });
}

const { default: mermaid } = await import('mermaid');
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

const diagramFiles = (inputs) => {
    const resolved = [];
    for (const input of inputs) {
        // Tolerate an unexpanded glob so the command reads the same in every shell.
        const target = input.replace(/[\\/]\*\.mmd$/, '');
        if (statSync(target).isDirectory()) {
            resolved.push(
                ...readdirSync(target)
                    .filter((name) => name.endsWith('.mmd'))
                    .sort()
                    .map((name) => join(target, name)),
            );
        } else {
            resolved.push(target);
        }
    }
    return resolved;
};

const inputs = process.argv.slice(2);
if (!inputs.length) {
    console.error('Usage: node scripts/check-diagram-syntax.mjs <file.mmd|directory> [more...]');
    process.exit(2);
}

const paths = diagramFiles(inputs);
if (!paths.length) {
    console.error('No .mmd files found. Generate them first with backend/tools/dump_diagrams.py.');
    process.exit(2);
}

let failed = false;
for (const path of paths) {
    const definition = readFileSync(path, 'utf8');
    try {
        await mermaid.parse(definition);
        console.log(`OK    ${path}`);
    } catch (error) {
        failed = true;
        console.log(`FAIL  ${path}`);
        console.log(String(error.message || error).split('\n').slice(0, 12).join('\n'));
    }
}
process.exit(failed ? 1 : 0);
