//go:build windows

package winfilepicker_test

import (
	"errors"
	"fmt"

	winfilepicker "FNE/winfilepicker"
)

func ExampleSelectFile() {
	path, err := winfilepicker.SelectFile("Please select an image", []string{"jpg", "jpeg", "png", "gif"})
	if errors.Is(err, winfilepicker.ErrCancelled) {
		fmt.Println("cancelled")
		return
	}
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("selected:", path)
}

func ExampleSelectFiles() {
	paths, err := winfilepicker.SelectFiles("Please select images", []string{"*.jpg", "*.png", "*.gif"})
	if errors.Is(err, winfilepicker.ErrCancelled) {
		fmt.Println("cancelled")
		return
	}
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for i, p := range paths {
		fmt.Println(i+1, p)
	}
}

func ExampleSelectFolder() {
	path, err := winfilepicker.SelectFolder("Please select a folder")
	if errors.Is(err, winfilepicker.ErrCancelled) {
		fmt.Println("cancelled")
		return
	}
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("selected:", path)
}

func ExampleSelectFolders() {
	paths, err := winfilepicker.SelectFolders("Please select folders")
	if errors.Is(err, winfilepicker.ErrCancelled) {
		fmt.Println("cancelled")
		return
	}
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	for i, p := range paths {
		fmt.Println(i+1, p)
	}
}
