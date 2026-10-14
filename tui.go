package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-runewidth"
	"golang.org/x/term"
)

const (
	KeyArrowUp = 1000 + iota
	KeyArrowDown
	KeyArrowLeft
	KeyArrowRight
	KeyEnter
	KeyBackspace
	KeyEsc
	KeyCtrlC
)

const (
	colorAccent = "\x1b[38;2;255;92;0m"
	colorText2  = "\x1b[38;2;188;183;175m"
	colorText3  = "\x1b[38;2;145;141;134m"
	colorHint   = "\x1b[90m"
	colorReset  = "\x1b[0m"
)

// keyReader decodes raw terminal input into logical key codes
type keyReader struct {
	keys chan rune
}

// newKeyReader starts background goroutines that decode terminal input including escape sequences
func newKeyReader() *keyReader {
	k := &keyReader{keys: make(chan rune, 16)}
	raw := make(chan rune, 16)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			r, _, err := reader.ReadRune()
			if err != nil {
				close(raw)
				return
			}
			raw <- r
		}
	}()
	go func() {
		for {
			r, ok := <-raw
			if !ok {
				close(k.keys)
				return
			}
			if r != '\x1b' {
				switch r {
				case '\r', '\n':
					k.keys <- KeyEnter
				case 3:
					k.keys <- KeyCtrlC
				case 8, 127:
					k.keys <- KeyBackspace
				default:
					k.keys <- r
				}
				continue
			}
			select {
			case next := <-raw:
				if next == '[' {
					k.consumeCSI(raw)
				} else if next > 0 && next < 0x80 {
					k.keys <- next | 0x80
				} else {
					k.keys <- next
				}
			case <-time.After(25 * time.Millisecond):
				k.keys <- KeyEsc
			}
		}
	}()
	return k
}

// consumeCSI reads a control sequence and forwards arrow keys while discarding the rest
func (k *keyReader) consumeCSI(raw chan rune) {
	var final rune
	for {
		r, ok := <-raw
		if !ok {
			return
		}
		if r >= 0x40 && r <= 0x7e {
			final = r
			break
		}
	}
	switch final {
	case 'A':
		k.keys <- KeyArrowUp
	case 'B':
		k.keys <- KeyArrowDown
	case 'C':
		k.keys <- KeyArrowRight
	case 'D':
		k.keys <- KeyArrowLeft
	}
}

// readLine reads one line of terminal input through the shared key reader
func readLine(kr *keyReader, prompt string) string {
	logInput(prompt)
	fmt.Print("\x1b[?25h")
	defer fmt.Print("\x1b[?25l")
	var b strings.Builder
	for {
		key := <-kr.keys
		if key == KeyEnter {
			fmt.Print("\r\n")
			return strings.TrimSpace(b.String())
		}
		if key >= 32 && key < KeyArrowUp {
			b.WriteRune(key)
			fmt.Print(string(key))
		}
	}
}

// enterRawMode switches the terminal into raw input mode, hides the cursor and returns the previous state
func enterRawMode() (*term.State, error) {
	fmt.Print("\x1b[?25l")
	return term.MakeRaw(int(os.Stdin.Fd()))
}

// leaveRawMode restores the terminal state and makes the cursor visible again
func leaveRawMode(oldState *term.State) {
	if oldState != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
	}
	fmt.Print("\x1b[?25h")
}

// termSize returns the current terminal width and height
func termSize() (int, int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// clearScreen clears the terminal including the scrollback and homes the cursor
func clearScreen() {
	fmt.Print("\x1b[2J\x1b[3J\x1b[H")
}

// visibleWidth returns the display width of a string ignoring ANSI escape sequences
func visibleWidth(text string) int {
	w := 0
	inEsc := false
	for _, r := range text {
		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == '\x1b' {
			inEsc = true
			continue
		}
		w += runewidth.RuneWidth(r)
	}
	return w
}

// centerLine pads a line with spaces so it appears centered within the given width
func centerLine(text string, width int) string {
	tw := visibleWidth(text)
	if tw >= width {
		return text
	}
	pad := (width - tw) / 2
	return strings.Repeat(" ", pad) + text
}

// truncateWidth cuts a string so its display width does not exceed the limit
func truncateWidth(text string, limit int) string {
	if visibleWidth(text) <= limit {
		return text
	}
	var b strings.Builder
	w := 0
	inEsc := false
	for _, r := range text {
		if inEsc {
			b.WriteRune(r)
			if r == 'm' {
				inEsc = false
			}
			continue
		}
		if r == '\x1b' {
			inEsc = true
			b.WriteRune(r)
			continue
		}
		rw := runewidth.RuneWidth(r)
		if w+rw > limit-1 {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	b.WriteString("…")
	return b.String()
}

// downloadStatus holds the shared download state rendered by the TUI
type downloadStatus struct {
	mu      sync.Mutex
	lines   []string
	done    int
	total   int
	lastErr string
}

// update replaces the rendered status lines and counters
func (s *downloadStatus) update(lines []string, done, total int, lastErr string) {
	s.mu.Lock()
	s.lines = lines
	s.done = done
	s.total = total
	s.lastErr = lastErr
	s.mu.Unlock()
}

// snapshot returns the current status for rendering
func (s *downloadStatus) snapshot() ([]string, int, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lines, s.done, s.total, s.lastErr
}

// runDownloadUI renders the download status page and returns true when the user pressed Ctrl+C
func runDownloadUI(kr *keyReader, status *downloadStatus, port int) bool {
	lastFrame := ""
	for {
		w, h := termSize()
		lines, done, total, lastErr := status.snapshot()
		var b strings.Builder
		b.WriteString("\x1b[2J\x1b[3J\x1b[H")
		b.WriteString("\r\n\r\n")
		b.WriteString(centerLine(colorAccent+"在线下载"+colorReset, w))
		b.WriteString("\r\n\r\n")
		b.WriteString(centerLine(colorText2+fmt.Sprintf("http://127.0.0.1:%d", port)+colorReset, w))
		b.WriteString("\r\n\r\n")
		b.WriteString(centerLine(colorText3+fmt.Sprintf("%d / %d", done, total)+colorReset, w))
		b.WriteString("\r\n\r\n")
		maxLines := max(h-12, 1)
		shown := lines
		if len(shown) > maxLines {
			shown = shown[len(shown)-maxLines:]
		}
		for _, l := range shown {
			b.WriteString(centerLine(colorText2+truncateWidth(l, w-4)+colorReset, w))
			b.WriteString("\r\n")
		}
		if lastErr != "" {
			b.WriteString("\r\n")
			b.WriteString(centerLine(colorAccent+truncateWidth(lastErr, w-2)+colorReset, w))
			b.WriteString("\r\n")
		}
		fmt.Fprintf(&b, "\x1b[%d;1H", h)
		b.WriteString(centerLine(colorHint+downloadQuitHint()+colorReset, w))
		frame := b.String()
		if frame != lastFrame {
			fmt.Print(frame)
			lastFrame = frame
		}
		select {
		case key := <-kr.keys:
			if key == KeyCtrlC {
				return true
			}
			if key == 'q' || key == 'Q' || key == KeyEsc {
				return false
			}
		case <-time.After(300 * time.Millisecond):
		}
	}
}
