import { ImportEntry } from "./import-matcher";

export function parseCSV(csvText: string): ImportEntry[] {
  const lines = csvText.split(/\r?\n/).filter(line => line.trim() !== "");
  if (lines.length < 2) return [];

  const headers = lines[0].split(",").map(h => h.trim().toLowerCase());
  const entries: ImportEntry[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i]);
    if (values.length !== headers.length) continue;

    const entry: Partial<ImportEntry> = {};
    
    headers.forEach((header, index) => {
      const val = values[index].trim();
      
      if (header === "title" || header === "name" || header === "manga" || header === "series") {
        entry.title = val;
      } else if (header === "status" || header === "state") {
        entry.status = val;
      } else if (header === "progress" || header === "chapters" || header === "read" || header === "last_read") {
        entry.progress = parseInt(val, 10) || 0;
      } else if (header === "external_id" || header === "id") {
        entry.external_id = val;
      } else if (header === "source" || header === "platform") {
        entry.source_platform = val;
      }
    });

    if (entry.title) {
      entries.push({
        title: entry.title,
        status: entry.status || "reading",
        progress: entry.progress ?? 0,
        external_id: entry.external_id,
        source_platform: entry.source_platform
      });
    }
  }

  return entries;
}

function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}
