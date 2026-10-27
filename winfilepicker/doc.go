//go:build windows

// Package winfilepicker opens modern native Windows file and folder
// selection dialogs through the IFileOpenDialog COM interface, without any
// external dependencies.
//
// The package exposes four calls: SelectFile, SelectFiles, SelectFolder and
// SelectFolders. Every dialog is shown in the Explorer visual style and its
// taskbar, title bar and Alt-Tab icon is the Windows File Explorer icon
// instead of the generic application icon. If the Explorer icon cannot be
// loaded, the dialogs keep the system default icon.
//
// Cancelling a dialog is reported as an error for which
// errors.Is(err, ErrCancelled) returns true, so callers can distinguish user
// cancellation from real failures.
//
// Dialogs are shown with per-monitor DPI awareness for the duration of the
// call, so they render crisply on scaled displays, and their icons are
// extracted at the display's native size. The process wide DPI awareness of
// the host application is left untouched.
package winfilepicker
