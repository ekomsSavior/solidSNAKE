// harness/store_ref.go - dev-only oracle for the solidSNAKE store parity check.
//
// Replays the exact operation script used by tests/test_store.cpp --report
// against the real Ranger C3 store package (and its go-sqlite3 driver) and
// prints the same canonical JSON report. scripts/interop.sh diffs the two.
//
// Usage: go run ./cmd/storeref <dir>
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	_ "github.com/mattn/go-sqlite3"

	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/protocol"
	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/store"
)

type step struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

func jImplant(r *protocol.ImplantRecord) map[string]any {
	return map[string]any{
		"id":           r.ID,
		"impl_type":    r.Type,
		"target_proc":  r.TargetProc,
		"hostname":     r.Hostname,
		"arch":         r.Arch,
		"first_seen":   "TS",
		"last_seen":    "TS",
		"beacon_count": r.BeaconCount,
		"tasks_sent":   r.TasksSent,
		"tasks_done":   r.TasksDone,
		"jitter_score": r.JitterScore,
		"dns_enabled":  r.DNSEnabled,
		"mesh_enabled": r.MeshEnabled,
		"flagged":      r.Flagged,
		"node_id":      r.NodeID,
	}
}

func jTask(t protocol.Task) map[string]any {
	o := map[string]any{
		"id":      "TID",
		"type":    t.Type,
		"payload": t.Payload,
		"ts":      "TS",
	}
	if t.TTL != 0 {
		o["ttl"] = t.TTL
	}
	return o
}

func jMesh(n protocol.MeshNode) map[string]any {
	return map[string]any{
		"id":        n.ID,
		"addr":      n.Addr,
		"pubkey":    nil, // ListMeshNodes does not select the column
		"last_seen": "TS",
		"implants":  n.Implants,
		"version":   n.Version,
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: storeref <dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	die(os.RemoveAll(dir))
	die(os.MkdirAll(dir, 0o700))
	dbPath := filepath.Join(dir, "store-report.db")

	st, err := store.New(dbPath)
	die(err)
	defer st.Close()

	// Raw handle for PRAGMA/status introspection (same DB file).
	raw, err := sql.Open("sqlite3", dbPath)
	die(err)
	defer raw.Close()

	steps := []step{}
	add := func(name string, value any) { steps = append(steps, step{name, value}) }

	// schema
	schema := map[string]any{}
	for _, t := range []string{"implants", "tasks", "mesh_nodes", "exfil_data", "operators"} {
		rows, err := raw.Query("PRAGMA table_info(" + t + ")")
		die(err)
		cols := []string{}
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull int
			var dflt any
			var pk int
			die(rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk))
			cols = append(cols, name+":"+typ)
		}
		die(rows.Err())
		rows.Close()
		schema[t] = cols
	}
	add("schema", schema)

	// 1. upsert + read back
	a := &protocol.ImplantRecord{
		ID: "imp-1", Type: "linux", TargetProc: "t1", Hostname: "h1",
		Arch: "x86_64", JitterScore: 0.5, DNSEnabled: true,
	}
	die(st.UpsertImplant(a))
	got, err := st.GetImplant("imp-1")
	die(err)
	add("upsert_imp1_get", jImplant(got))

	// 2. second beacon with empty target/hostname
	a.TargetProc = ""
	a.Hostname = ""
	a.JitterScore = 0.75
	a.NodeID = ""
	die(st.UpsertImplant(a))
	got, err = st.GetImplant("imp-1")
	die(err)
	add("upsert_imp1_again_get", jImplant(got))

	// 3. second implant, all defaults
	b := &protocol.ImplantRecord{ID: "imp-2", Type: "windows"}
	die(st.UpsertImplant(b))
	got, err = st.GetImplant("imp-2")
	die(err)
	add("upsert_imp2_get", jImplant(got))

	// 4. list + count
	impls, err := st.ListImplants()
	die(err)
	ids := []string{}
	for _, i := range impls {
		ids = append(ids, i.ID)
	}
	sort.Strings(ids)
	add("list_ids", ids)
	n, err := st.ImplantCount()
	die(err)
	add("count", n)

	// 5. tasks
	t1, err := st.CreateTask("imp-1", "shell", "primary", map[string]any{"command": "id"})
	die(err)
	add("create_task1", jTask(*t1))
	t2, err := st.CreateTask("imp-1", "payload", "dns", map[string]any{"name": "sysrecon"})
	die(err)
	add("create_task2", jTask(*t2))

	pend, err := st.PendingTasks("imp-1")
	die(err)
	jp := []any{}
	for _, t := range pend {
		jp = append(jp, jTask(t))
	}
	add("pending_first", jp)
	pend2, err := st.PendingTasks("imp-1")
	die(err)
	add("pending_second_count", len(pend2))
	got, err = st.GetImplant("imp-1")
	die(err)
	add("imp1_after_pending", jImplant(got))

	// 6. complete the first task
	die(st.CompleteTask(t1.ID, &protocol.TaskResult{TaskID: t1.ID, Success: true, Output: "ok"}))
	add("complete_task1", map[string]any{"ok": true})

	statusOf := func(id string) string {
		var s string
		die(raw.QueryRow("SELECT status FROM tasks WHERE id = ?", id).Scan(&s))
		return s
	}
	add("task1_status", statusOf(t1.ID))
	add("task2_status", statusOf(t2.ID))
	got, err = st.GetImplant("imp-1")
	die(err)
	add("imp1_after_complete", jImplant(got))

	// 7. exfil blob
	die(st.ExfilData("imp-1", "screenshot", "dns", []byte("ABC")))
	var impID, dtype, channel string
	var data []byte
	die(raw.QueryRow("SELECT implant_id, data_type, data, channel FROM exfil_data").
		Scan(&impID, &dtype, &data, &channel))
	add("exfil_row", []any{impID, dtype, string(data), channel})

	// 8. mesh node upsert + conflict update
	die(st.UpsertMeshNode(&protocol.MeshNode{ID: "m-1", Addr: "10.0.0.2:9000", PublicKey: []byte("PK"), Implants: 3, Version: "3.0.0"}))
	die(st.UpsertMeshNode(&protocol.MeshNode{ID: "m-1", Addr: "10.0.0.3:9000", Implants: 4, Version: "3.0.0"}))
	nodes, err := st.ListMeshNodes()
	die(err)
	jm := []any{}
	for _, n := range nodes {
		jm = append(jm, jMesh(n))
	}
	add("mesh_list", jm)

	// 9. missing implant error text
	_, missErr := st.GetImplant("nope")
	add("missing_implant_error", missErr.Error())

	out, err := json.MarshalIndent(map[string]any{"steps": steps}, "", "  ")
	die(err)
	fmt.Println(string(out))
}
