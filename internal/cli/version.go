package cli

import (
	"runtime"
	"runtime/debug"
	"strings"
)

func buildVersion() string {
	version := "(devel)"
	details := []string{runtime.Version()}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" {
			version = info.Main.Version
		}
		modified := false
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision := setting.Value
				if len(revision) > 12 {
					revision = revision[:12]
				}
				details = append(details, "revision "+revision)
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		if modified {
			details = append(details, "uncommitted changes")
		}
	}
	details = append(details, "active by default")
	return "php2shell " + version + " (" + strings.Join(details, "; ") + ")"
}
