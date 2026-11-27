import fs from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const CAMOUFOX_PACKAGE = 'camoufox';

export function isPackageEntryResolvable(packageName, source = import.meta) {
    try {
        const packagePath = typeof source.resolve === 'function'
            ? fileURLToPath(source.resolve(packageName))
            : createRequire(source.url).resolve(packageName);
        return fs.statSync(packagePath).isFile();
    } catch {
        return false;
    }
}

export function isCamoufoxModuleResolvable() {
    return isPackageEntryResolvable(CAMOUFOX_PACKAGE);
}

export function loadCamoufoxModule() {
    return import(CAMOUFOX_PACKAGE);
}
