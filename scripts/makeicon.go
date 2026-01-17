// +build ignore

package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "Icon.png")
	}
	
	// Create a 512x512 icon with indigo color and a magnifying glass shape
	img := image.NewRGBA(image.Rect(0, 0, 512, 512))
	
	// Background - dark blue/indigo
	bgColor := color.RGBA{17, 24, 39, 255}
	accentColor := color.RGBA{99, 102, 241, 255}
	
	// Fill background
	for y := 0; y < 512; y++ {
		for x := 0; x < 512; x++ {
			img.Set(x, y, bgColor)
		}
	}
	
	// Draw a simple magnifying glass circle
	cx, cy := 220, 200
	radius := 120
	thickness := 20
	
	for y := 0; y < 512; y++ {
		for x := 0; x < 512; x++ {
			dx := x - cx
			dy := y - cy
			dist := dx*dx + dy*dy
			
			// Ring of the magnifying glass
			inner := (radius - thickness) * (radius - thickness)
			outer := (radius + thickness) * (radius + thickness)
			
			if dist >= inner && dist <= outer {
				img.Set(x, y, accentColor)
			}
		}
	}
	
	// Draw handle
	for i := 0; i < 150; i++ {
		for j := -15; j < 15; j++ {
			x := 300 + i
			y := 300 + i + j
			if x < 512 && y < 512 && x >= 0 && y >= 0 {
				img.Set(x, y, accentColor)
			}
		}
	}
	
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	
	png.Encode(f, img)
}

