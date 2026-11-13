package scanner

import (
	"strings"
	"testing"
)

func TestExtractDependencies(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},
	  "node_modules/lodash":{"version":"4.17.0"},
	  "node_modules/a/node_modules/@scope/b":{"version":"2.0.0"},
	  "node_modules/linked":{"version":"1.0.0","link":true},
	  "node_modules/evil name; rm -rf":{"version":"1.0.0"},
	  "node_modules/badver":{"version":"1.0.0\n<script>"}}}`
	got := ExtractDependencies("package-lock.json", []byte(lock))
	names := map[string]string{}
	for _, d := range got {
		names[d.Name] = d.Version
		if d.Ecosystem != "npm" {
			t.Errorf("ecosystem %q", d.Ecosystem)
		}
	}
	if len(names) != 2 || names["lodash"] != "4.17.0" || names["@scope/b"] != "2.0.0" {
		t.Errorf("npm deps = %v", names)
	}

	legacy := `{"lockfileVersion":1,"dependencies":{"x":{"version":"1.0.0","dependencies":{"y":{"version":"2.0.0"}}}}}`
	if got := ExtractDependencies("package-lock.json", []byte(legacy)); len(got) != 2 {
		t.Errorf("lockfile v1 deps = %v", got)
	}

	mod := "module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/text v0.3.0 // indirect\n)\nrequire github.com/c/d v0.1.0\nreplace github.com/a/b => ../b\n"
	g := ExtractDependencies("sub/go.mod", []byte(mod))
	if len(g) != 3 || g[0].Ecosystem != "Go" || strings.HasPrefix(g[0].Version, "v") {
		t.Errorf("go deps = %v", g)
	}

	req := "# comment\nFlask==2.0.1\nrequests[security]==2.25.0 ; python_version>'3'\nnumpy>=1.0\n-r other.txt\nMy_Pkg==1.0\n"
	p := ExtractDependencies("requirements.txt", []byte(req))
	got2 := map[string]string{}
	for _, d := range p {
		got2[d.Name] = d.Version
	}
	if len(got2) != 3 || got2["flask"] != "2.0.1" || got2["requests"] != "2.25.0" || got2["my-pkg"] != "1.0" {
		t.Errorf("pypi deps = %v", got2)
	}

	if len(ExtractDependencies("README.md", []byte("x"))) != 0 || len(ExtractDependencies("package-lock.json", []byte("not json"))) != 0 {
		t.Error("unsupported or invalid input should yield nothing")
	}
}

func TestAdvisoryFindingRejectsHostileValues(t *testing.T) {
	d := Dependency{"npm", "pkg", "1.0.0", "package-lock.json"}
	if _, ok := AdvisoryFinding(d, Advisory{ID: "bad id with spaces"}); ok {
		t.Error("hostile advisory id accepted")
	}
	if _, ok := AdvisoryFinding(Dependency{"npm", "x\ny", "1.0.0", "p"}, Advisory{ID: "GHSA-aaaa-bbbb-cccc"}); ok {
		t.Error("hostile package name accepted")
	}
	f, ok := AdvisoryFinding(d, Advisory{ID: "GHSA-aaaa-bbbb-cccc", Severity: "nonsense"})
	if !ok || f.Severity != SeverityMedium {
		t.Errorf("unknown severity should default to medium: %+v", f)
	}
	f2, _ := AdvisoryFinding(d, Advisory{ID: "GHSA-aaaa-bbbb-cccc"})
	if f.Fingerprint == "" || f.Fingerprint != f2.Fingerprint {
		t.Error("fingerprint must be stable")
	}
}
