// Shared snapshot file layer (Self-Heal Discipline Spec, files/m2/
// self-heal-discipline-spec.md §2/§3). ONE implementation for every
// JS-side state takeover (sysproxy today; the app also READS the Go
// helper's netcfg-backup.json through this layer — the format is shared,
// the helper implements the same semantics in Go).
//
// Guarantees provided here, and only here:
//   - atomic writes (tmp file in the same directory + rename);
//   - read classification: { kind: "none" | "corrupt" | "ok", data? } —
//     a caller-supplied validator decides what counts as corrupt;
//   - removal as a plain fs operation (the CALLER decides when removal is
//     allowed: spec R3, only after a verified restore).
// The iron rule (R1: never overwrite a held snapshot) and the self-heal
// state machine live in the domain modules, not here.
import fs from "node:fs";
import path from "node:path";

export function snapshotPath(dir, filename) {
  return path.join(dir, filename);
}

export function writeSnapshotAtomic(dir, filename, data) {
  fs.mkdirSync(dir, { recursive: true });
  const stem = filename.replace(/\.json$/, "");
  const tmp = path.join(dir, `${stem}.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n");
  fs.renameSync(tmp, snapshotPath(dir, filename));
}

// validate(parsed) -> normalized data, or null when the content is not a
// snapshot this caller recognizes (wrong version, missing fields, ...).
export function readSnapshot(dir, filename, validate) {
  const file = snapshotPath(dir, filename);
  if (!fs.existsSync(file)) return { kind: "none" };
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    const data = validate(parsed);
    if (!data) return { kind: "corrupt" };
    return { kind: "ok", data };
  } catch {
    return { kind: "corrupt" };
  }
}

export function removeSnapshot(dir, filename) {
  fs.rmSync(snapshotPath(dir, filename), { force: true });
}
