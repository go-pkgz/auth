package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/rrivera/identicon"
)

func main() {

	// transparentBg := func(cb []byte, fc color.Color) color.Color {
	//      return color.Transparent
	// }

	namespaces := []string{
		"",
		"itx",
		"github",
	}

	usernames := []string{
		"rrivera",
		"abc123",
		"modulo",
		"johndoe",
	}

	sizes := [][]int{
		{5, 3},
		{7, 4},
		{10, 7},
	}

	for _, ns := range namespaces {
		for _, s := range sizes {
			ig, _ := identicon.New(ns, s[0], s[1]) // , identicon.SetBackgroundColorFunction(transparentBg)
			for _, u := range usernames {
				ii, _ := ig.Draw(u)
				sizeStr := strconv.Itoa(s[0])
				img, _ := os.Create("./" + sizeStr + "x" + sizeStr + "/" + strings.Replace(ii.GeneratorText(), ":", "_", -1) + ".png")
				ii.Png(260, img)
				img.Close()
			}
		}
	}
}
