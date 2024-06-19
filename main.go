package main

import "github.com/deepfence/PacketStreamer/cmd"

func main() {
	cmd.Execute()
}

// go build -ldflags="-s -w"  -buildvcs=false   -o PacketStreamer.exe  .\main.go
// PacketStreamer.exe -
