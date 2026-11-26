import fs from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const CAMOUFOX_PACKAGE = 'camoufox';

export function isCamoufoxModuleResolvable() {
    try {
        const packagePath = typeof import.meta.resolve === 'function'
            ? fileURLToPath(import.meta.resolve(CAMOUFOX_PACKAGE))
            : createRequire(import.meta.url).resolve(CAMOUFOX_PACKAGE);
        return fs.statSync(packagePath).isFile();
    } catch {
        return false;
    }
}

export function loadCamoufoxModule() {
    return import(CAMOUFOX_PACKAGE);
}
