import { applyPrefsToDocument, loadPrefs } from "./lib/prefs";
export function preboot(): void {
    try {
        applyPrefsToDocument(loadPrefs());
    }
    catch {
    }
}
preboot();
