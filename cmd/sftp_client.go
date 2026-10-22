// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/francoismichel/ssh3"
	client "github.com/francoismichel/ssh3/client"
	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
)

// Client side of the file-transfer mode: `ssh3 -transfer SRC DST` with
// exactly one scp-style operand `user@host:remote_path`; the other operand is
// local. The transfer mode lives under the -transfer long form since the
// CLI-parity wave (CTO_TASK §7c row 1): -f is the ssh(1) background flag now.

type transferTarget struct {
	username   string
	hostname   string
	remotePath string
	port       int
	urlPath    string
}

func isRemoteTransferSpec(operand string) bool {
	// a remote operand always carries a user part ("user@host:remote_path"):
	// the transfer client needs an explicit username, and requiring "@"
	// keeps local paths (including Windows "C:\..." ones) unambiguous
	at := strings.Index(operand, "@")
	if at <= 0 {
		return false
	}
	return strings.Contains(operand[at:], ":")
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, symbol := range value {
		if symbol < '0' || symbol > '9' {
			return false
		}
	}
	return true
}

// parseRemoteTransferSpec accepts "user@host:remote_path" and the explicit
// "user@host:port/url_path:remote_path" form; returns the target with the
// effective port and URL path.
func parseRemoteTransferSpec(spec string, defaultPort int, defaultURLPath string) (transferTarget, int, string, error) {
	target := transferTarget{port: defaultPort, urlPath: defaultURLPath}
	hostnamePart := spec
	if at := strings.Index(hostnamePart, "@"); at >= 0 {
		target.username = hostnamePart[:at]
		hostnamePart = hostnamePart[at+1:]
	}
	parts := strings.Split(hostnamePart, ":")
	if len(parts) < 2 || parts[0] == "" {
		return target, defaultPort, defaultURLPath, fmt.Errorf("%q is not a remote operand (expected user@host:remote_path)", spec)
	}
	target.hostname = parts[0]
	if len(parts) == 2 {
		target.remotePath = parts[1]
		// "user@host/url_path:remote" hybrid: a slash in the host part is the
		// connection URL path (mirrors the plain client's URL form)
		if slash := strings.Index(target.hostname, "/"); slash >= 0 {
			target.urlPath = target.hostname[slash:]
			target.hostname = target.hostname[:slash]
		}
	} else if len(parts) == 3 {
		portPart, urlRest, found := strings.Cut(parts[1], "/")
		if !digitsOnly(portPart) {
			return target, defaultPort, defaultURLPath, fmt.Errorf("%q has an invalid port %q", spec, portPart)
		}
		target.port = atoi(portPart, defaultPort)
		target.urlPath = defaultURLPath
		if found {
			target.urlPath = "/" + urlRest
		}
		target.remotePath = parts[2]
	} else {
		return target, defaultPort, defaultURLPath, fmt.Errorf("%q has too many ':' separators", spec)
	}
	if target.remotePath == "" {
		return target, defaultPort, defaultURLPath, fmt.Errorf("%q is missing the remote path", spec)
	}
	return target, target.port, target.urlPath, nil
}

func atoi(value string, fallback int) int {
	number := 0
	for _, symbol := range value {
		number = number*10 + int(symbol-'0')
	}
	if number == 0 {
		return fallback
	}
	return number
}

// buildTransferURL assembles the connection URL for a transfer target, with
// the port and URL path resolved from the operand (or -P/-U defaults).
func buildTransferURL(target transferTarget) *url.URL {
	return &url.URL{
		Scheme: "https",
		User:   url.User(target.username),
		Host:   fmt.Sprintf("%s:%d", target.hostname, target.port),
		Path:   target.urlPath,
	}
}

const checksumAutoThreshold = 32 * 1024 * 1024 // bytes; verify re-read kicks in automatically above it

const sftpChannelType = "sftp"

// runFileTransfer performs one upload or download over a dedicated "sftp"
// channel of an already authenticated client.
func runFileTransfer(client *client.Client, target transferTarget, localPath string, upload bool, recursive bool, resumeMode bool, verifyChecksum bool) int {
	channel, err := client.OpenChannel(sftpChannelType, 30000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open sftp channel: %+v\n", err)
		return -1
	}
	rwc := ssh3.NewChannelReadWriteCloser(channel)
	sftpClient, err := sftp.NewClientPipe(rwc, rwc, sftp.UseConcurrentWrites(true))
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start sftp client: %+v\n", err)
		channel.Close()
		return -1
	}
	defer func() {
		if err := sftpClient.Close(); err != nil {
			log.Debug().Msgf("sftp client close: %s", err)
		}
	}()

	remotePath := target.remotePath
	if upload {
		if recursive {
			return uploadDir(sftpClient, localPath, remotePath, resumeMode, verifyChecksum)
		}
		return uploadFile(sftpClient, localPath, remotePath, resumeMode, verifyChecksum)
	}
	if recursive {
		return downloadDir(sftpClient, remotePath, localPath, resumeMode, verifyChecksum)
	}
	return downloadFile(sftpClient, remotePath, localPath, resumeMode, verifyChecksum)
}

// sftpMkdirAll creates remote directories level by level (pkg/sftp Mkdir is
// single-level) and tolerates existing ones.
func sftpMkdirAll(sftpClient *sftp.Client, remoteDir string) error {
	current := ""
	for _, segment := range strings.Split(path.Clean(remoteDir), "/") {
		if segment == "" {
			current = "/"
			continue
		}
		current = path.Join(current, segment)
		if err := sftpClient.Mkdir(current); err != nil {
			if info, statErr := sftpClient.Stat(current); statErr == nil && info.IsDir() {
				continue
			}
			return err
		}
	}
	return nil
}

// sftpTreeWorkers is the pipeline depth of the recursive transfers: files
// are pushed without waiting for the previous file's confirmation. SFTP
// requests are id-multiplexed over the channel, the server's RequestServer
// worker pool processes them concurrently, and CLOSE still waits for its own
// file's writes — so per-file confirmations and integrity hold while the
// client never stalls on a round-trip between files.
const sftpTreeWorkers = 16

func uploadDir(sftpClient *sftp.Client, localRoot, remoteRoot string, resumeMode, verifyChecksum bool) int {
	info, err := os.Stat(localRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat %s: %s\n", localRoot, err)
		return -1
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is not a directory: drop -r for a single-file transfer\n", localRoot)
		return -1
	}
	if err := sftpMkdirAll(sftpClient, remoteRoot); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create remote directory %s: %s\n", remoteRoot, err)
		return -1
	}
	progress := newTransferProgress("upload", localRoot, -1)
	files := make(chan string)
	var wg sync.WaitGroup
	var failures atomic.Int64
	worker := func() {
		defer wg.Done()
		for localPath := range files {
			relative, err := filepath.Rel(localRoot, localPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot relativize %s: %s\n", localPath, err)
				failures.Add(1)
				continue
			}
			remotePath := path.Join(remoteRoot, filepath.ToSlash(relative))
			progress.rename(path.Base(localPath))
			if code := uploadFileInTree(sftpClient, localPath, remotePath, resumeMode, verifyChecksum, progress); code != 0 {
				failures.Add(1)
			}
		}
	}
	for i := 0; i < sftpTreeWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	// the walk itself is local and fast: it creates the remote directories on
	// the way and feeds the workers, then closes the pipeline
	walkErr := filepath.WalkDir(localRoot, func(current string, entry fs.DirEntry, callbackErr error) error {
		if callbackErr != nil {
			return callbackErr
		}
		relative, err := filepath.Rel(localRoot, current)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if current == localRoot {
				return nil
			}
			return sftpMkdirAll(sftpClient, path.Join(remoteRoot, filepath.ToSlash(relative)))
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		files <- current
		return nil
	})
	close(files)
	wg.Wait()
	progress.finish()
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "upload walk failed: %s\n", walkErr)
		return -1
	}
	if failed := failures.Load(); failed > 0 {
		fmt.Fprintf(os.Stderr, "upload finished with %d failed file(s)\n", failed)
		return -1
	}
	return 0
}

func downloadDir(sftpClient *sftp.Client, remoteRoot, localRoot string, resumeMode, verifyChecksum bool) int {
	remoteInfo, err := sftpClient.Stat(remoteRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat remote %s: %s\n", remoteRoot, err)
		return -1
	}
	if !remoteInfo.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is not a remote directory: drop -r for a single-file transfer\n", remoteRoot)
		return -1
	}
	if err := os.MkdirAll(localRoot, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localRoot, err)
		return -1
	}
	progress := newTransferProgress("download", remoteRoot, -1)
	type treeFile struct {
		remote, relative string
		size             int64
		modTime          time.Time
	}
	files := make(chan treeFile)
	var wg sync.WaitGroup
	var failures atomic.Int64
	worker := func() {
		defer wg.Done()
		for entry := range files {
			localPath := filepath.Join(localRoot, filepath.FromSlash(entry.relative))
			progress.rename(path.Base(localPath))
			if code := downloadFileInTree(sftpClient, entry.remote, localPath, entry.size, entry.modTime, resumeMode, verifyChecksum, progress); code != 0 {
				failures.Add(1)
			}
		}
	}
	for i := 0; i < sftpTreeWorkers; i++ {
		wg.Add(1)
		go worker()
	}
	// the walk enumerates the remote tree (ReadDir round-trips, serial by
	// nature) in a producer goroutine while the workers download
	var walkFailures atomic.Int64
	go func() {
		defer close(files)
		walker := sftpClient.Walk(remoteRoot)
		for walker.Step() {
			if walker.Err() != nil {
				fmt.Fprintf(os.Stderr, "walk error at %s: %s\n", walker.Path(), walker.Err())
				walkFailures.Add(1)
				continue
			}
			relative, err := filepath.Rel(remoteRoot, walker.Path())
			if err != nil {
				continue
			}
			localPath := filepath.Join(localRoot, filepath.FromSlash(relative))
			if walker.Stat().IsDir() {
				if err := os.MkdirAll(localPath, 0o755); err != nil {
					fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localPath, err)
					walkFailures.Add(1)
				}
				continue
			}
			if !walker.Stat().Mode().IsRegular() {
				continue
			}
			files <- treeFile{remote: walker.Path(), relative: relative, size: walker.Stat().Size(), modTime: walker.Stat().ModTime()}
		}
	}()
	wg.Wait()
	progress.finish()
	if failed := walkFailures.Load() + failures.Load(); failed > 0 {
		fmt.Fprintf(os.Stderr, "download finished with %d failed file(s)\n", failed)
		return -1
	}
	return 0
}

// downloadFileTo downloads a remote file into an exact local path (no
// directory-guessing), used by recursive downloads.
func downloadFileTo(sftpClient *sftp.Client, remotePath, localPath string, resumeMode, verifyChecksum bool) int {
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open remote file %s: %s\n", remotePath, err)
		return -1
	}
	defer remoteFile.Close()

	info, err := remoteFile.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat remote file %s: %s\n", remotePath, err)
		return -1
	}

	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	var startOffset int64
	if resumeMode {
		if localInfo, err := os.Stat(localPath); err == nil {
			switch {
			case localInfo.Size() > info.Size():
				fmt.Fprintf(os.Stderr, "local %s is larger than remote (%d > %d bytes); remove it or drop --continue\n",
					localPath, localInfo.Size(), info.Size())
				return -1
			case localInfo.Size() == info.Size() && localInfo.ModTime().Unix() == info.ModTime().Unix():
				fmt.Fprintf(os.Stderr, "%s is already up to date (same size and mtime), skipping\n", localPath)
				return 0
			case localInfo.Size() == info.Size():
				// the size alone cannot prove the content: a remote file
				// rewritten in place keeps its size, so trust the mtime the
				// previous download inherited and re-transfer (R7)
				fmt.Fprintf(os.Stderr, "%s matches in size but the mtime differs, re-transferring\n", localPath)
			default:
				startOffset = localInfo.Size()
				openFlags = os.O_WRONLY
			}
		}
	}

	localFile, err := os.OpenFile(localPath, openFlags, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localPath, err)
		return -1
	}
	defer localFile.Close()

	localHasher := sha256.New()
	if startOffset > 0 {
		if prefixFile, err := os.Open(localPath); err == nil {
			io.Copy(localHasher, io.NewSectionReader(prefixFile, 0, startOffset))
			prefixFile.Close()
		}
	}

	progress := newTransferProgress("download", path.Base(remotePath), info.Size()-startOffset)
	if _, err := io.Copy(io.MultiWriter(localFile, localHasher), progress.wrapReader(remoteFile)); err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %s\n", err)
		return -1
	}
	progress.finish()

	if verifyChecksum || info.Size() > checksumAutoThreshold {
		if !verifyRemoteChecksum(sftpClient, remotePath, localHasher) {
			fmt.Fprintf(os.Stderr, "checksum mismatch after download of %s\n", remotePath)
			return -1
		}
		fmt.Fprintf(os.Stderr, "[ssh3 -f] checksum ok: %s\n", remotePath)
	}
	// inherit the remote mtime so the next --continue can skip by size+mtime
	// (R7); a failure is not fatal — it costs one redundant download later
	modTime := info.ModTime()
	if err := os.Chtimes(localPath, modTime, modTime); err != nil {
		fmt.Fprintf(os.Stderr, "cannot set mtime on %s: %s\n", localPath, err)
	}
	return 0
}

// verifyRemoteChecksum re-reads the remote file end to end and compares its
// SHA-256 with the local one; returns true when they match.
func verifyRemoteChecksum(sftpClient *sftp.Client, remotePath string, localHasher hash.Hash) bool {
	remoteHasher := sha256.New()
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checksum verification failed: %s\n", err)
		return false
	}
	defer remoteFile.Close()
	if _, err := io.Copy(remoteHasher, remoteFile); err != nil {
		fmt.Fprintf(os.Stderr, "checksum verification failed: %s\n", err)
		return false
	}
	return bytes.Equal(localHasher.Sum(nil), remoteHasher.Sum(nil))
}

func uploadFile(sftpClient *sftp.Client, localPath, remotePath string, resumeMode, verifyChecksum bool) int {
	info, err := os.Stat(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat %s: %s\n", localPath, err)
		return -1
	}
	if info.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is a directory: use -r for recursive transfer\n", localPath)
		return -1
	}
	// a remote path pointing at an existing directory receives the file
	// under its local base name, scp-style
	if info, err := sftpClient.Stat(remotePath); err == nil && info.IsDir() {
		remotePath = path.Join(remotePath, path.Base(localPath))
	}

	// auto-create missing parent directories so uploads into fresh
	// destinations work without a manual mkdir
	if dir := path.Dir(remotePath); dir != "." && dir != "/" {
		if _, err := sftpClient.Stat(dir); err != nil {
			if err := sftpMkdirAll(sftpClient, dir); err != nil {
				fmt.Fprintf(os.Stderr, "cannot create remote directory %s: %s\n", dir, err)
				return -1
			}
		}
	}

	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	var startOffset int64
	if resumeMode {
		if remoteInfo, err := sftpClient.Stat(remotePath); err == nil {
			switch {
			case remoteInfo.Size() > info.Size():
				fmt.Fprintf(os.Stderr, "remote %s is larger than local (%d > %d bytes); remove it or drop --continue\n",
					remotePath, remoteInfo.Size(), info.Size())
				return -1
			case remoteInfo.Size() == info.Size() && remoteInfo.ModTime().Unix() == info.ModTime().Unix():
				fmt.Fprintf(os.Stderr, "%s is already up to date (same size and mtime), skipping\n", remotePath)
				return 0
			case remoteInfo.Size() == info.Size():
				// the size alone cannot prove the content: a source rewritten
				// in place keeps its size, so trust the stamped mtime instead
				// and re-transfer (R7)
				fmt.Fprintf(os.Stderr, "%s matches in size but the mtime differs, re-transferring\n", remotePath)
			default:
				startOffset = remoteInfo.Size()
				openFlags = os.O_WRONLY // append via absolute writes from startOffset
			}
		}
	}

	localFile, err := os.Open(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %s\n", localPath, err)
		return -1
	}
	defer localFile.Close()

	remoteFile, err := sftpClient.OpenFile(remotePath, openFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create remote file %s: %s\n", remotePath, err)
		return -1
	}
	defer remoteFile.Close()

	localHasher := sha256.New()
	var reader io.Reader = localFile
	if startOffset > 0 {
		if _, err := localFile.Seek(startOffset, io.SeekStart); err != nil {
			fmt.Fprintf(os.Stderr, "cannot resume %s: %s\n", localPath, err)
			return -1
		}
		reader = io.NewSectionReader(localFile, startOffset, info.Size()-startOffset)
		hashResumePrefix(sftpClient, remotePath, startOffset, localHasher)
	}

	progress := newTransferProgress("upload", localPath, info.Size()-startOffset)
	_, err = copyWithOffset(remoteFile, reader, progress.addBytes, localHasher, startOffset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload failed: %s\n", err)
		return -1
	}
	progress.finish()

	remoteInfo, err := sftpClient.Stat(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot verify remote file %s: %s\n", remotePath, err)
		return -1
	}
	if remoteInfo.Size() != info.Size() {
		fmt.Fprintf(os.Stderr, "size mismatch after upload: local %d bytes, remote %d bytes\n", info.Size(), remoteInfo.Size())
		return -1
	}
	if verifyChecksum || info.Size() > checksumAutoThreshold {
		if !verifyRemoteChecksum(sftpClient, remotePath, localHasher) {
			fmt.Fprintf(os.Stderr, "checksum mismatch after upload of %s\n", remotePath)
			return -1
		}
		fmt.Fprintf(os.Stderr, "[ssh3 -f] checksum ok: %s\n", remotePath)
	}
	// stamp the remote with the source's mtime: the --continue skip decision
	// compares size+mtime (R7); a failure here only costs one redundant
	// re-transfer on the next run, never data
	if err := sftpClient.Chtimes(remotePath, info.ModTime(), info.ModTime()); err != nil {
		fmt.Fprintf(os.Stderr, "cannot set mtime on %s: %s\n", remotePath, err)
	}
	return 0
}

// uploadFileInTree is the recursive-transfer fast path: the walk has already
// created every directory, so the per-file round-trips shrink to the SFTP
// minimum — OPEN, the data writes, CLOSE (whose status confirms the file's
// writes). The scp-style dir-target Stat, the parent-dir Stat/Mkdir and the
// post-upload size Stat of uploadFile are dropped from the hot path;
// --checksum and the automatic big-file threshold still re-read when asked.
func uploadFileInTree(sftpClient *sftp.Client, localPath, remotePath string, resumeMode, verifyChecksum bool, progress *transferProgress) int {
	info, err := os.Stat(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat %s: %s\n", localPath, err)
		return -1
	}
	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	var startOffset int64
	if resumeMode {
		if remoteInfo, err := sftpClient.Stat(remotePath); err == nil {
			switch {
			case remoteInfo.Size() > info.Size():
				fmt.Fprintf(os.Stderr, "remote %s is larger than local (%d > %d bytes); remove it or drop --continue\n",
					remotePath, remoteInfo.Size(), info.Size())
				return -1
			case remoteInfo.Size() == info.Size() && remoteInfo.ModTime().Unix() == info.ModTime().Unix():
				fmt.Fprintf(os.Stderr, "%s is already up to date (same size and mtime), skipping\n", remotePath)
				return 0
			case remoteInfo.Size() == info.Size():
				// the size alone cannot prove the content: a source rewritten
				// in place keeps its size, so trust the stamped mtime instead
				// and re-transfer (R7)
				fmt.Fprintf(os.Stderr, "%s matches in size but the mtime differs, re-transferring\n", remotePath)
			default:
				startOffset = remoteInfo.Size()
				openFlags = os.O_WRONLY // append via absolute writes from startOffset
			}
		}
	}
	localFile, err := os.Open(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %s\n", localPath, err)
		return -1
	}
	defer localFile.Close()
	remoteFile, err := sftpClient.OpenFile(remotePath, openFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create remote file %s: %s\n", remotePath, err)
		return -1
	}
	defer remoteFile.Close()
	localHasher := sha256.New()
	var reader io.Reader = localFile
	if startOffset > 0 {
		if _, err := localFile.Seek(startOffset, io.SeekStart); err != nil {
			fmt.Fprintf(os.Stderr, "cannot resume %s: %s\n", localPath, err)
			return -1
		}
		reader = io.NewSectionReader(localFile, startOffset, info.Size()-startOffset)
		hashResumePrefix(sftpClient, remotePath, startOffset, localHasher)
	}
	if _, err := copyWithOffset(remoteFile, reader, progress.addBytes, localHasher, startOffset); err != nil {
		fmt.Fprintf(os.Stderr, "upload failed: %s\n", err)
		return -1
	}
	if verifyChecksum || info.Size() > checksumAutoThreshold {
		if !verifyRemoteChecksum(sftpClient, remotePath, localHasher) {
			fmt.Fprintf(os.Stderr, "checksum mismatch after upload of %s\n", remotePath)
			return -1
		}
		fmt.Fprintf(os.Stderr, "[ssh3 -f] checksum ok: %s\n", remotePath)
	}
	// stamp the remote with the source's mtime: the --continue skip decision
	// compares size+mtime (R7), so without the stamp the next run would
	// re-transfer the file once more. A failure is not fatal — it costs one
	// redundant transfer later, never data
	if err := sftpClient.Chtimes(remotePath, info.ModTime(), info.ModTime()); err != nil {
		fmt.Fprintf(os.Stderr, "cannot set mtime on %s: %s\n", remotePath, err)
	}
	return 0
}

// downloadFileInTree is the recursive-transfer fast path: the walk already
// carries the entry size and mtime, so the per-file remote Stat disappears —
// OPEN, the reads, CLOSE carry the transfer.
func downloadFileInTree(sftpClient *sftp.Client, remotePath, localPath string, size int64, modTime time.Time, resumeMode, verifyChecksum bool, progress *transferProgress) int {
	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	var startOffset int64
	if resumeMode {
		if localInfo, err := os.Stat(localPath); err == nil {
			switch {
			case localInfo.Size() > size:
				fmt.Fprintf(os.Stderr, "local %s is larger than remote (%d > %d bytes); remove it or drop --continue\n",
					localPath, localInfo.Size(), size)
				return -1
			case localInfo.Size() == size && localInfo.ModTime().Unix() == modTime.Unix():
				fmt.Fprintf(os.Stderr, "%s is already up to date (same size and mtime), skipping\n", localPath)
				return 0
			case localInfo.Size() == size:
				// the size alone cannot prove the content: a remote file
				// rewritten in place keeps its size, so trust the mtime the
				// previous download inherited and re-transfer (R7)
				fmt.Fprintf(os.Stderr, "%s matches in size but the mtime differs, re-transferring\n", localPath)
			default:
				startOffset = localInfo.Size()
				openFlags = os.O_WRONLY
			}
		}
	}
	localFile, err := os.OpenFile(localPath, openFlags, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localPath, err)
		return -1
	}
	defer localFile.Close()
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open remote file %s: %s\n", remotePath, err)
		return -1
	}
	defer remoteFile.Close()
	localHasher := sha256.New()
	if startOffset > 0 {
		if prefixFile, err := os.Open(localPath); err == nil {
			io.Copy(localHasher, io.NewSectionReader(prefixFile, 0, startOffset))
			prefixFile.Close()
		}
	}
	if _, err := io.Copy(io.MultiWriter(localFile, localHasher), progress.wrapReader(remoteFile)); err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %s\n", err)
		return -1
	}
	if verifyChecksum || size > checksumAutoThreshold {
		if !verifyRemoteChecksum(sftpClient, remotePath, localHasher) {
			fmt.Fprintf(os.Stderr, "checksum mismatch after download of %s\n", remotePath)
			return -1
		}
		fmt.Fprintf(os.Stderr, "[ssh3 -f] checksum ok: %s\n", remotePath)
	}
	// inherit the remote mtime so the next --continue can skip by size+mtime
	// (R7); a failure is not fatal — it costs one redundant download later
	if err := os.Chtimes(localPath, modTime, modTime); err != nil {
		fmt.Fprintf(os.Stderr, "cannot set mtime on %s: %s\n", localPath, err)
	}
	return 0
}

// copyWithOffset streams src into an absolute-offset writer (pkg/sftp files
// write at explicit offsets, so resumable uploads append from startOffset),
// feeding progress and the running hash.
func copyWithOffset(dest io.WriterAt, src io.Reader, onBytes func(int64), hasher io.Writer, startOffset int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, writeErr := dest.WriteAt(buf[:n], startOffset+written); writeErr != nil {
				return written, writeErr
			}
			written += int64(n)
			if onBytes != nil {
				onBytes(int64(n))
			}
			if hasher != nil {
				hasher.Write(buf[:n])
			}
		}
		if readErr == io.EOF {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

// hashResumePrefix folds the already-transferred prefix into the local hash
// so a resumed upload's final checksum covers the whole file.
func hashResumePrefix(sftpClient *sftp.Client, remotePath string, length int64, hasher io.Writer) {
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return
	}
	defer remoteFile.Close()
	limited := io.NewSectionReader(remoteFile, 0, length)
	io.Copy(hasher, limited)
}

func downloadFile(sftpClient *sftp.Client, remotePath, localPath string, resumeMode, verifyChecksum bool) int {
	remoteInfo, err := sftpClient.Stat(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat remote %s: %s\n", remotePath, err)
		return -1
	}
	if remoteInfo.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is a remote directory: use -r for recursive transfer\n", remotePath)
		return -1
	}
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		localPath = filepath.Join(localPath, path.Base(remotePath))
	}
	return downloadFileTo(sftpClient, remotePath, localPath, resumeMode, verifyChecksum)
}

// transferProgress reports byte counts on stderr every 500ms and a final
// summary line; it is wired into the copy path by wrapping reader/writer.
type transferProgress struct {
	label    string
	name     string
	total    int64
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	addBytes func(int64)
}

func newTransferProgress(label, name string, total int64) *transferProgress {
	p := &transferProgress{
		label: label,
		name:  name,
		total: total,
		done:  make(chan struct{}),
	}
	var transferred atomic.Int64
	p.addBytes = func(n int64) { transferred.Add(n) }
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				fmt.Fprintf(os.Stderr, "[ssh3 -f] %s %s: %s done\n", label, p.currentName(), humanBytes(transferred.Load()))
				return
			case <-ticker.C:
				done := transferred.Load()
				if p.total > 0 {
					fmt.Fprintf(os.Stderr, "\r[ssh3 -f] %s %s: %s / %s (%d%%)",
						label, p.currentName(), humanBytes(done), humanBytes(p.total), done*100/p.total)
				} else {
					fmt.Fprintf(os.Stderr, "\r[ssh3 -f] %s %s: %s", label, p.currentName(), humanBytes(done))
				}
			}
		}
	}()
	return p
}

// rename switches the displayed file name (recursive transfers walk many
// files under one progress ticker).
func (p *transferProgress) rename(name string) {
	p.mu.Lock()
	p.name = name
	p.mu.Unlock()
}

func (p *transferProgress) currentName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name
}

func (p *transferProgress) finish() {
	p.once.Do(func() { close(p.done) })
}

type progressReader struct {
	reader io.Reader
	p      *transferProgress
}

func (p *transferProgress) wrapReader(reader io.Reader) io.Reader {
	if p.addBytes == nil {
		return reader
	}
	return &progressReader{reader: reader, p: p}
}

func (r *progressReader) Read(buf []byte) (int, error) {
	n, err := r.reader.Read(buf)
	if n > 0 {
		r.p.addBytes(int64(n))
	}
	return n, err
}

type progressWriter struct {
	writer io.Writer
	p      *transferProgress
}

func (p *transferProgress) wrapWriter(writer io.Writer) io.Writer {
	if p.addBytes == nil {
		return writer
	}
	return &progressWriter{writer: writer, p: p}
}

func (w *progressWriter) Write(buf []byte) (int, error) {
	n, err := w.writer.Write(buf)
	if n > 0 {
		w.p.addBytes(int64(n))
	}
	return n, err
}

func humanBytes(count int64) string {
	const unit = 1024
	if count < unit {
		return fmt.Sprintf("%d B", count)
	}
	value := float64(count)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	index := -1
	for value >= unit && index < len(units)-1 {
		value /= unit
		index++
	}
	return fmt.Sprintf("%.1f %s", value, units[index])
}
