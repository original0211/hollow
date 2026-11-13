// App-side reader for the helper's netcfg backup (netcfg-backup.json) —
// RF-21-02 format interop. The file is WRITTEN by the Go helper; the app
// reads it for self-checks, status display, and the app-driven restore
// path. The structural criteria mirror the helper's own validation
// (self-heal spec §2 + RF-21-04) and the snapshot.js classification
// style: kind is "none" | "corrupt" | "ok", and a structurally
// incomplete file is corrupt — never "mostly fine".
//
// This module does not write the file and never modifies it.

import fs from "node:fs";
import path from "node:path";

export const NETCFG_BACKUP_FILE = "netcfg-backup.json";
export const NETCFG_SNAPSHOT_VERSION = 1;
export const NETCFG_ADAPTER_NAME = "Hollow";

function checkState(state, side, problems) {
  if (state === null || typeof state !== "object") {
    problems.push(`${side}: missing`);
    return;
  }
  if (typeof state.defaultGateway !== "string" || state.defaultGateway === "") {
    problems.push(`${side}.defaultGateway: missing`);
  }
  const adapter = state.adapter;
  if (adapter === null || typeof adapter !== "object" || adapter.name !== NETCFG_ADAPTER_NAME) {
    problems.push(`${side}.adapter.name: must be ${NETCFG_ADAPTER_NAME}`);
  }
  if (!Array.isArray(state.addedRoutes)) {
    problems.push(`${side}.addedRoutes: must be an array (present, may be empty)`);
  } else {
    for (const [i, r] of state.addedRoutes.entries()) {
      if (typeof r?.dest !== "string" || typeof r?.gateway !== "string") {
        problems.push(`${side}.addedRoutes[${i}]: dest/gateway required`);
      }
    }
  }
}

// classifyNetcfgBackup(text) -> { kind, snapshot?, problems }
// text: the file's contents, or null when the file does not exist.
export function classifyNetcfgBackup(text) {
  if (text === null || text === undefined) return { kind: "none", problems: [] };
  let snap;
  try {
    snap = JSON.parse(text);
  } catch {
    return { kind: "corrupt", problems: ["unparseable JSON"] };
  }
  const problems = [];
  if (snap?.version !== NETCFG_SNAPSHOT_VERSION) problems.push("version: unsupported");
  if (typeof snap?.takenAt !== "string" || snap.takenAt === "") problems.push("takenAt: missing");
  checkState(snap?.original, "original", problems);
  checkState(snap?.written, "written", problems);
  if (problems.length > 0) return { kind: "corrupt", problems };
  return { kind: "ok", snapshot: snap, problems: [] };
}

export function readNetcfgBackup(homeDir) {
  const file = path.join(homeDir, NETCFG_BACKUP_FILE);
  let text = null;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    text = null; // absent (or unreadable → the helper's own check governs)
  }
  return classifyNetcfgBackup(text);
}

// The routes a restore must remove, per the backup — the app-side mirror
// of the helper's PlanRestore route set (canonical dest+gateway pairs).
export function restorableRoutes(snapshot) {
  if (!snapshot) return [];
  return (snapshot.written?.addedRoutes ?? []).map((r) => ({ dest: r.dest, gateway: r.gateway, interface: r.interface ?? "" }));
}
