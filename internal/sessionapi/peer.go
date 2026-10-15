// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/alban/hallpass/internal/procfs"
)

var connectParams = grpc.ConnectParams{
	Backoff:           backoff.Config{BaseDelay: 50 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: time.Second},
	MinConnectTimeout: 5 * time.Second,
}

// peerCreds checks the peer of each connection in the handshake, and
// reports the result in its AuthInfo: rejecting the connection there would
// close it without telling the client why.
type peerCreds struct{}

type peerInfo struct {
	err error // why the peer may not call the session; nil if it may
}

func (peerInfo) AuthType() string { return "peercred" }

func (peerCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return c, peerInfo{errors.New("not a unix socket")}, nil
	}
	return c, peerInfo{checkPeer(uc)}, nil
}

func (peerCreds) ClientHandshake(_ context.Context, _ string, c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c, peerInfo{}, nil
}

func (peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (p peerCreds) Clone() credentials.TransportCredentials { return p }

func (peerCreds) OverrideServerName(string) error { return nil }

func checkAuth(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "unknown peer")
	}
	info, ok := p.AuthInfo.(peerInfo)
	if !ok {
		return status.Error(codes.PermissionDenied, "unknown peer")
	}
	if info.err != nil {
		return status.Error(codes.PermissionDenied, info.err.Error())
	}
	return nil
}

// checkPeer rejects clients that could be the sandbox answering its own
// prompts: the peer must be the same user and must not run under any seccomp
// filter (every sandboxed process runs under hallpass's filter, and filters
// cannot be removed).
func checkPeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if int(cred.Uid) != os.Getuid() {
		return errors.New("peer is a different user")
	}
	if procfs.SeccompMode(int(cred.Pid)) != 0 {
		return errors.New("peer runs under a seccomp filter (sandboxed processes cannot answer)")
	}
	return nil
}
