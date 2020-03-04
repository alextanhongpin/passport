package connector

import "strings"

var table = "login"

func SetTable(t string) {
	t = strings.TrimSpace(t)
	if t != "" {
		table = t
	}
}
