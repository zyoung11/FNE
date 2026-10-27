//go:build windows

package winfilepicker

import (
	"testing"
)

func TestNormalizeExt(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"jpg", "jpg"},
		{".jpg", "jpg"},
		{"*.jpg", "jpg"},
		{" *.jpg ", "jpg"},
		{"png", "png"},
		{"", ""},
		{" ", ""},
		{"*.", ""},
		{".", ""},
	}
	for _, c := range cases {
		if got := normalizeExt(c.input); got != c.want {
			t.Fatalf("normalizeExt(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestBuildFilterSpec(t *testing.T) {
	specs, err := buildFilterSpec([]string{"jpg", ".png", "*.gif", " "})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 {
		t.Fatalf("len(specs) = %d, want 1", len(specs))
	}
	if name := utf16PtrToString(specs[0].pszName); name != "Supported Files" {
		t.Fatalf("name = %q, want %q", name, "Supported Files")
	}
	if spec := utf16PtrToString(specs[0].pszSpec); spec != "*.jpg;*.png;*.gif" {
		t.Fatalf("spec = %q, want %q", spec, "*.jpg;*.png;*.gif")
	}
}

func TestBuildFilterSpecEmpty(t *testing.T) {
	specs, err := buildFilterSpec(nil)
	if err != nil {
		t.Fatal(err)
	}
	if specs != nil {
		t.Fatalf("specs = %v, want nil", specs)
	}
}
