// Keeps headlamp/ out of the hallpass module: node_modules contains .go
// files that would break `go build ./...` and `go test ./...`.
module github.com/alban/hallpass/headlamp

go 1.24
