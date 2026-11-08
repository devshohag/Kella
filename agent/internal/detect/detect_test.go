package detect

import (
	"reflect"
	"testing"
)

func TestMatch(t *testing.T) {
	postfixInstalled = func() bool { return true }

	tests := []struct {
		name     string
		running  []string
		detected []string
		guards   []string
	}{
		{"bare server", []string{"sshd", "systemd"}, []string{}, []string{"server"}},
		{"mail server", []string{"master", "dovecot", "sshd"}, []string{"dovecot", "postfix"}, []string{"mail", "server"}},
		{"web with php", []string{"nginx", "php-fpm8.3", "mysqld"}, []string{"mysql", "nginx", "php-fpm"}, []string{"database", "server", "web"}},
		{"voice", []string{"asterisk", "kamailio"}, []string{"asterisk", "kamailio"}, []string{"server", "voice"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]bool{}
			for _, p := range tc.running {
				m[p] = true
			}
			d, g := Match(m)
			if !reflect.DeepEqual(d, tc.detected) {
				t.Errorf("detected = %v, want %v", d, tc.detected)
			}
			if !reflect.DeepEqual(g, tc.guards) {
				t.Errorf("guards = %v, want %v", g, tc.guards)
			}
		})
	}
}
