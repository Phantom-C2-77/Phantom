package payloads

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Category colors — Material Design palette, looks professional on any launcher
var categoryColors = map[string]color.RGBA{
	"productivity":  {0x42, 0x85, 0xF4, 0xFF}, // Google Blue
	"utility":       {0x0F, 0x9D, 0x58, 0xFF}, // Green
	"social":        {0xE9, 0x1E, 0x63, 0xFF}, // Pink
	"security":      {0x67, 0x3A, 0xB7, 0xFF}, // Deep Purple
	"finance":       {0xFF, 0x98, 0x00, 0xFF}, // Amber
	"entertainment": {0xFF, 0x57, 0x22, 0xFF}, // Deep Orange
	"corporate":     {0x1A, 0x23, 0x7E, 0xFF}, // Indigo
	"default":       {0x21, 0x96, 0xF3, 0xFF}, // Blue
}

// Icon overlay symbols (drawn as simple shapes)
var categoryShapes = map[string]string{
	"productivity":  "grid",    // grid/calculator
	"utility":       "bolt",    // lightning bolt
	"social":        "bubble",  // chat bubble
	"security":      "shield",  // shield
	"finance":       "coin",    // circle/coin
	"entertainment": "play",    // play triangle
	"corporate":     "building", // building
	"default":       "shield",
}

// GenerateAppIcon creates a professional-looking 192x192 PNG icon
// with a colored circular background and a white symbol overlay.
func GenerateAppIcon(category string) []byte {
	size := 192
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	bgColor, ok := categoryColors[category]
	if !ok {
		bgColor = categoryColors["default"]
	}

	cx, cy := float64(size)/2, float64(size)/2
	radius := float64(size) / 2

	// Draw filled circle background with slight gradient
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist <= radius-1 {
				// Subtle radial gradient — lighter at top-left
				gradientFactor := 1.0 - (dist/radius)*0.15 - (float64(y)/float64(size))*0.1
				r := clampByte(float64(bgColor.R) * gradientFactor)
				g := clampByte(float64(bgColor.G) * gradientFactor)
				b := clampByte(float64(bgColor.B) * gradientFactor)
				img.Set(x, y, color.RGBA{r, g, b, 255})
			} else if dist <= radius {
				// Anti-aliased edge
				alpha := uint8(255 - uint8((dist-radius+1)*255))
				img.Set(x, y, color.RGBA{bgColor.R, bgColor.G, bgColor.B, alpha})
			}
		}
	}

	// Draw white symbol overlay
	white := color.RGBA{255, 255, 255, 230}
	shape := categoryShapes[category]
	if shape == "" {
		shape = categoryShapes["default"]
	}

	switch shape {
	case "shield":
		drawShield(img, size, white)
	case "bolt":
		drawBolt(img, size, white)
	case "bubble":
		drawBubble(img, size, white)
	case "grid":
		drawGrid(img, size, white)
	case "coin":
		drawCoin(img, size, white)
	case "play":
		drawPlay(img, size, white)
	case "building":
		drawBuilding(img, size, white)
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func clampByte(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

func fillRect(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA) {
	for y := y1; y < y2; y++ {
		for x := x1; x < x2; x++ {
			img.Set(x, y, c)
		}
	}
}

func fillCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx := float64(x - cx)
			dy := float64(y - cy)
			if dx*dx+dy*dy <= float64(r*r) {
				img.Set(x, y, c)
			}
		}
	}
}

// Shield shape — security apps
func drawShield(img *image.RGBA, size int, c color.RGBA) {
	cx := size / 2
	top := size / 4
	bottom := size * 3 / 4
	width := size / 3

	for y := top; y < bottom; y++ {
		progress := float64(y-top) / float64(bottom-top)
		var w int
		if progress < 0.6 {
			w = width
		} else {
			w = int(float64(width) * (1.0 - (progress-0.6)/0.4))
		}
		for x := cx - w; x <= cx+w; x++ {
			img.Set(x, y, c)
		}
	}
	// Checkmark inside
	check := color.RGBA{categoryColors["security"].R, categoryColors["security"].G, categoryColors["security"].B, 255}
	midY := (top + bottom) / 2
	for i := 0; i < size/8; i++ {
		fillRect(img, cx-size/6+i, midY+i-2, cx-size/6+i+4, midY+i+2, check)
	}
	for i := 0; i < size/5; i++ {
		fillRect(img, cx-size/12+i, midY+size/8-i-2, cx-size/12+i+4, midY+size/8-i+2, check)
	}
}

// Lightning bolt — utility apps
func drawBolt(img *image.RGBA, size int, c color.RGBA) {
	cx := size / 2
	// Simple zigzag bolt
	points := [][2]int{
		{cx + size/12, size / 4},
		{cx - size/8, size/2 - size/16},
		{cx + size/16, size/2 - size/16},
		{cx - size/12, size * 3 / 4},
		{cx + size/8, size/2 + size/16},
		{cx - size/16, size/2 + size/16},
	}
	for i := 0; i < len(points)-1; i += 1 {
		drawThickLine(img, points[i][0], points[i][1], points[(i+1)%len(points)][0], points[(i+1)%len(points)][1], 4, c)
	}
	// Fill the bolt shape
	for y := size / 4; y < size*3/4; y++ {
		for x := cx - size/6; x < cx+size/6; x++ {
			dx := float64(x-cx) / float64(size/6)
			dy := float64(y-size/2) / float64(size/4)
			if math.Abs(dx-dy*0.3) < 0.5 {
				img.Set(x, y, c)
			}
		}
	}
}

// Chat bubble — social apps
func drawBubble(img *image.RGBA, size int, c color.RGBA) {
	cx, cy := size/2, size/2-size/12
	rx, ry := size/3, size/4
	// Ellipse
	for y := cy - ry; y <= cy+ry; y++ {
		for x := cx - rx; x <= cx+rx; x++ {
			dx := float64(x-cx) / float64(rx)
			dy := float64(y-cy) / float64(ry)
			if dx*dx+dy*dy <= 1.0 {
				img.Set(x, y, c)
			}
		}
	}
	// Tail
	for i := 0; i < size/6; i++ {
		w := size/6 - i
		fillRect(img, cx-size/6, cy+ry+i-2, cx-size/6+w, cy+ry+i, c)
	}
	// Three dots inside
	dotC := color.RGBA{categoryColors["social"].R, categoryColors["social"].G, categoryColors["social"].B, 255}
	fillCircle(img, cx-size/8, cy, size/20, dotC)
	fillCircle(img, cx, cy, size/20, dotC)
	fillCircle(img, cx+size/8, cy, size/20, dotC)
}

// Grid — productivity apps
func drawGrid(img *image.RGBA, size int, c color.RGBA) {
	gap := size / 20
	cellSize := (size/2 - gap*2) / 2
	startX := size/2 - cellSize - gap/2
	startY := size/2 - cellSize - gap/2
	for row := 0; row < 2; row++ {
		for col := 0; col < 2; col++ {
			x := startX + col*(cellSize+gap)
			y := startY + row*(cellSize+gap)
			// Rounded rectangle
			for py := y; py < y+cellSize; py++ {
				for px := x; px < x+cellSize; px++ {
					img.Set(px, py, c)
				}
			}
		}
	}
}

// Coin circle — finance apps
func drawCoin(img *image.RGBA, size int, c color.RGBA) {
	cx, cy := size/2, size/2
	r := size / 3
	// Outer ring
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx := float64(x-cx) / float64(r)
			dy := float64(y-cy) / float64(r)
			dist := dx*dx + dy*dy
			if dist <= 1.0 && dist >= 0.65 {
				img.Set(x, y, c)
			}
		}
	}
	// Dollar sign — vertical line + S shape
	for y := cy - r/2; y <= cy+r/2; y++ {
		img.Set(cx, y, c)
		img.Set(cx+1, y, c)
	}
	// S curves
	fillRect(img, cx-r/3, cy-r/4, cx+r/3, cy-r/4+4, c)
	fillRect(img, cx-r/3, cy, cx+r/3, cy+4, c)
	fillRect(img, cx-r/3, cy+r/4-4, cx+r/3, cy+r/4, c)
}

// Play triangle — entertainment apps
func drawPlay(img *image.RGBA, size int, c color.RGBA) {
	cx := size/2 + size/16 // offset right slightly
	cy := size / 2
	h := size / 3 // half height
	w := size / 4 // width

	for y := cy - h; y <= cy+h; y++ {
		progress := 1.0 - math.Abs(float64(y-cy))/float64(h)
		lineW := int(float64(w) * progress)
		for x := cx - w; x < cx-w+lineW; x++ {
			img.Set(x, y, c)
		}
	}
}

// Building — corporate apps
func drawBuilding(img *image.RGBA, size int, c color.RGBA) {
	// Main building
	bx := size/2 - size/6
	by := size / 3
	bw := size / 3
	bh := size * 5 / 12
	fillRect(img, bx, by, bx+bw, by+bh, c)

	// Windows (dark cutouts)
	winC := color.RGBA{categoryColors["corporate"].R, categoryColors["corporate"].G, categoryColors["corporate"].B, 255}
	winW := bw / 5
	winH := bh / 7
	for row := 0; row < 3; row++ {
		for col := 0; col < 2; col++ {
			wx := bx + bw/5 + col*(winW+bw/5)
			wy := by + bh/7 + row*(winH+bh/7)
			fillRect(img, wx, wy, wx+winW, wy+winH, winC)
		}
	}

	// Door
	dw := bw / 4
	dx := bx + bw/2 - dw/2
	dy := by + bh - bh/4
	fillRect(img, dx, dy, dx+dw, by+bh, winC)
}

func drawThickLine(img *image.RGBA, x1, y1, x2, y2, thickness int, c color.RGBA) {
	dx := float64(x2 - x1)
	dy := float64(y2 - y1)
	length := math.Sqrt(dx*dx + dy*dy)
	if length == 0 {
		return
	}
	steps := int(length)
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		px := int(float64(x1) + dx*t)
		py := int(float64(y1) + dy*t)
		for ty := py - thickness/2; ty <= py+thickness/2; ty++ {
			for tx := px - thickness/2; tx <= px+thickness/2; tx++ {
				img.Set(tx, ty, c)
			}
		}
	}
}
