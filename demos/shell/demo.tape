# Records demos/media/shell.mp4: a shell under hallpass. See demos/README.md.
#
# Run `make -C demos shell`. The Makefile runs it from the repository root
# and sets the output with `vhs -o`. Nothing is written outside the project:
# the write to ~/.bashrc is denied.

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "export PATH=$PWD:$PATH PS1='$ ' && rm -rf /tmp/hallpass-demo-shell && cp -r demos/example /tmp/hallpass-demo-shell && cd /tmp/hallpass-demo-shell && clear"
Enter
Sleep 500ms
Type@1ms `clear && printf '\n\n   \033[1mA shell under hallpass\033[0m\n\n   Writes inside the project go through.\n   Writes anywhere else wait for your answer.\n' && sleep 4 && clear`
Enter
Sleep 300ms
Show
Sleep 3.5s
Hide
Sleep 800ms
Show

Type "hallpass --allow-exec=@coreutils -- sh"
Sleep 300ms
Enter
Sleep 800ms
Type "# inside the project: no question"
Enter
Type "echo hello > notes.txt && cat notes.txt"
Sleep 300ms
Enter
Sleep 1.5s
Type "# outside: hallpass asks"
Enter
Type "echo '# pwned' >> ~/.bashrc"
Sleep 300ms
Enter
Wait+Screen@10s /wants to write/
Sleep 4s
Type "d"
Sleep 1.5s
Type "# Ctrl-] shows the rules and answers so far"
Enter
Sleep 1s
Ctrl+]
Sleep 5s
Type "q"
Sleep 500ms
Type "exit"
Enter
Sleep 1s
