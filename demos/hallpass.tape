# Records demos/hallpass.gif. See demos/README.md.
#
# Run from the repository root, after `go build -o hallpass ./cmd/hallpass`:
#   vhs demos/hallpass.tape

Output demos/hallpass.gif

Require copilot

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "export PATH=$PWD:$PATH PS1='$ ' && rm -rf /tmp/hallpass-demo && cp -r demos/example /tmp/hallpass-demo && cd /tmp/hallpass-demo && clear"
Enter
Sleep 500ms
Show

# 1. A shell in the sandbox: the project is writable, the rest is asked.
Type "hallpass -- sh"
Sleep 300ms
Enter
Sleep 800ms
Type "echo hello > notes.txt && cat notes.txt"
Sleep 300ms
Enter
Sleep 1s
Type "echo '# pwned' >> ~/.bashrc"
Sleep 300ms
Enter
Wait+Screen@10s /wants to write/
Sleep 2s
Type "d"
Sleep 1.5s
Ctrl+]
Sleep 3s
Type "q"
Sleep 500ms
Type "exit"
Enter
Sleep 1s

Hide
Type "rm -f notes.txt && clear"
Enter
Sleep 500ms
Show

# 2. An agent with every permission, building a project whose Makefile
# misbehaves.
Type "hallpass -allow ~/.copilot -allow ~/.cache/copilot -- copilot --yolo"
Sleep 300ms
Enter
Wait+Screen@60s /Check for mistakes/
Sleep 2s
Type "Build the project"
Sleep 500ms
Enter
Wait+Screen@120s /wants to write/
Sleep 2.5s
Type "d"
Wait+Screen@120s /Allow All/
Sleep 7s
Ctrl+C
Sleep 300ms
Ctrl+C
Sleep 1s
