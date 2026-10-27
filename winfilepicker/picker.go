//go:build windows

package winfilepicker

import "errors"

// ErrCancelled is returned when the user closes the dialog without making a selection.
var ErrCancelled = errors.New("winfilepicker: dialog cancelled")

// SelectFile opens a native file dialog and returns the path of the selected file.
// The title is shown in the dialog title bar; pass an empty string for the system default.
// Each entry of extensions filters the visible files and may be written as "jpg", ".jpg" or "*.jpg";
// pass nil or an empty slice to show all files.
// If the user cancels the dialog, ErrCancelled is returned.
func SelectFile(title string, extensions []string) (string, error) {
	paths, err := showOpenDialog(title, false, false, extensions)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", ErrCancelled
	}
	return paths[0], nil
}

// SelectFiles opens a native file dialog allowing multiple selection and returns
// the paths of all selected files. The title is shown in the dialog title bar;
// pass an empty string for the system default.
// Each entry of extensions filters the visible files and may be written as "jpg", ".jpg" or "*.jpg";
// pass nil or an empty slice to show all files.
// Selected items that resolve to no filesystem path are skipped.
// If the user cancels the dialog, ErrCancelled is returned.
func SelectFiles(title string, extensions []string) ([]string, error) {
	return showOpenDialog(title, true, false, extensions)
}

// SelectFolder opens a native folder dialog and returns the path of the selected folder.
// The title is shown in the dialog title bar; pass an empty string for the system default.
// If the user cancels the dialog, ErrCancelled is returned.
func SelectFolder(title string) (string, error) {
	paths, err := showOpenDialog(title, false, true, nil)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", ErrCancelled
	}
	return paths[0], nil
}

// SelectFolders opens a native folder dialog allowing multiple selection and
// returns the paths of all selected folders. The title is shown in the dialog
// title bar; pass an empty string for the system default.
// Selected items that resolve to no filesystem path are skipped.
// If the user cancels the dialog, ErrCancelled is returned.
func SelectFolders(title string) ([]string, error) {
	return showOpenDialog(title, true, true, nil)
}
