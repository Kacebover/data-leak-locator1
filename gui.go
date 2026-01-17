// Package main provides GUI launcher
package main

import (
	"fmt"
)

// LaunchGUI launches the GUI application (requires Fyne to be installed)
func LaunchGUI() {
	// Note: This is a placeholder for GUI launch
	// To use the GUI, compile the GUI version with:
	// go build -o data-leak-locator-gui ./cmd/gui
	//
	// The GUI version requires fyne to be available:
	// go get fyne.io/fyne/v2
	fmt.Println("To launch the GUI version, build the GUI from cmd/gui:")
	fmt.Println("  cd cmd/gui && go build -o ../../data-leak-locator-gui")
	fmt.Println("Then run: ./data-leak-locator-gui")
}
