# Records demos/media/coalesce.mp4: parallel writes outside the project give
# one prompt, and one answer settles them all. See demos/README.md.
#
# Run `make -C demos coalesce`. The Makefile runs it from the repository root,
# sets the output with `vhs -o` and gives a fresh directory as $DEMO_DIR, used
# as HOME: the demo writes nothing in yours.

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `export PATH=$PWD:$PATH PS1='$ ' HOME=$DEMO_DIR/home && mkdir -p $HOME/.cache/thumbs && cp -r demos/example $DEMO_DIR/project && cd $DEMO_DIR/project && clear`
Enter
Sleep 500ms
Type@1ms `clear && printf '\n\n   \033[1mPrompts that do not flood you\033[0m\n\n   Parallel writes under one folder wait behind one question,\n   and one answer settles them all.\n' && sleep 4 && clear`
Enter
Sleep 300ms
Show
Sleep 3.5s
Hide
Sleep 800ms
Show

Type "hallpass --allow-exec=@coreutils,@search -- sh"
Sleep 300ms
Enter
Sleep 800ms
Type "# 8 writes at once, outside the project"
Enter
Type "seq 8 | xargs -P8 -I{} touch ~/.cache/thumbs/{}.png"
Sleep 300ms
Enter
Wait+Screen@10s /wants to write/
Sleep 5s
# [a] always: allows the folder named in the prompt for the session.
Type "a"
Sleep 1.5s
Type "ls ~/.cache/thumbs"
Enter
Sleep 2s
Type "# the answer is a rule now: Ctrl-]"
Enter
Sleep 1s
Ctrl+]
Sleep 5s
Type "q"
Sleep 500ms
Type "exit"
Enter
Sleep 1s
