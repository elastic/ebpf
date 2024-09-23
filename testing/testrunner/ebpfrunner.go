// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package testrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type Runner struct {
	ctx    context.Context
	Cmd    *exec.Cmd
	Stdout io.ReadCloser
	Stderr io.ReadCloser

	StdoutChan chan string
	StderrChan chan string
	readChan   chan string
	doneChan   chan struct{}
	errChan    chan error

	InitMsg InitMsg
	t       *testing.T

	// buffers carry lifelong copy of stderr/stdout
	errBuff    []string
	outBuff    []string
	readCursor int
}

func runStreamChannel(sender chan string, errChan chan error, buffer *bufio.Scanner) {
	buf := make([]byte, 0, 64*1024)
	buffer.Buffer(buf, 1024*1024)
	go func() {
		for buffer.Scan() {
			line := buffer.Text()
			txt := strings.TrimSpace(line)
			if len(txt) > 0 {
				sender <- txt

			}
		}
		// the go testing libraries don't like it when you call
		// t.Fail() in a child thread; so we have to trickle down the failure
		if err := buffer.Err(); err != nil {
			errChan <- fmt.Errorf("error in buffer: %w", err)
			return
		}

	}()
}

func (runner *Runner) runIORead() {
	runner.readCursor = 0
	defer func() {
		close(runner.readChan)
	}()
	for {
		// this select case must never block, or else the underlying write() syscalls in EventsTrace
		// could block.
		select {
		case <-runner.doneChan:
			return
		case <-runner.ctx.Done():
			runner.t.Logf("got context done")
			return
		case line := <-runner.StderrChan:
			runner.errBuff = append(runner.errBuff, line)
		case line := <-runner.StdoutChan:
			runner.outBuff = append(runner.outBuff, line)
			select {
			case runner.readChan <- runner.outBuff[runner.readCursor]:
				runner.readCursor += 1
			default:
			}
		}
	}
}

func (runner *Runner) Start() {
	err := runner.Cmd.Start()
	require.NoError(runner.t, err)
	stderrStream := bufio.NewScanner(runner.Stderr)
	stdoutStream := bufio.NewScanner(runner.Stdout)

	runStreamChannel(runner.StdoutChan, runner.errChan, stdoutStream)
	runStreamChannel(runner.StderrChan, runner.errChan, stderrStream)

	go func() {
		runner.runIORead()
	}()

	// run until we get the first log line
	select {
	case <-runner.ctx.Done():
		runner.t.Fatalf("timed out while waiting for initial response from EventsTrace")
	case line := <-runner.readChan:
		err := json.Unmarshal([]byte(line), &runner.InitMsg)
		require.NoError(runner.t, err, "could not unmarshall json of first line. Stderr: \n", runner.errBuff)
	}
}

func (runner *Runner) GetNextEventOut(types ...string) string {
	ctx, cancel := context.WithTimeout(runner.ctx, time.Minute)
	defer cancel()

	type baseEvent struct {
		EventType string `json:"event_type"`
	}

	for {
		select {
		case <-ctx.Done():
			runner.t.Fatalf("timed out waiting for %v events", types)
		case err := <-runner.errChan:
			require.NoError(runner.t, err, "error reading from stdout/stderr in buffer")
		case line := <-runner.readChan:
			var resp baseEvent
			err := json.Unmarshal([]byte(line), &resp)
			require.NoError(runner.t, err, "error unmarshaling event_type from event %s", line)
			for _, evtType := range types {
				if evtType == resp.EventType {
					return line
				}
			}
		}
	}
}

func (runner *Runner) UnmarshalNextEvent(body any, types ...string) {
	line := runner.GetNextEventOut(types...)
	err := json.Unmarshal([]byte(line), &body)
	require.NoError(runner.t, err, "error unmarshaling JSON for types %v", types)
}

func (runner *Runner) Stop() {
	runner.doneChan <- struct{}{}
	err := runner.Cmd.Process.Kill()
	require.NoError(runner.t, err)

	_, err = runner.Cmd.Process.Wait()
	require.NoError(runner.t, err)
}

func (runner *Runner) Dump() {
	runner.t.Logf("STDOUT: \n")
	for _, line := range runner.outBuff {
		runner.t.Logf("%s", line)
	}
	runner.t.Logf("STDERR: \n")
	for _, line := range runner.errBuff {
		runner.t.Logf("%s", line)
	}
}

func NewEbpfRunner(ctx context.Context, t *testing.T, args ...string) *Runner {
	testRunner := &Runner{
		ctx:        ctx,
		StdoutChan: make(chan string, 1024),
		StderrChan: make(chan string, 1024),
		readChan:   make(chan string, 1024),
		doneChan:   make(chan struct{}),
		errChan:    make(chan error, 1),
		t:          t,
	}
	args = append(args, "--print-features-on-init", "--unbuffer-stdout", "--libbpf-verbose")
	testRunner.Cmd = exec.CommandContext(ctx, eventsTracePath, args...)

	var err error
	testRunner.Stdout, err = testRunner.Cmd.StdoutPipe()
	require.NoError(t, err, "failed to redirect stdout")

	testRunner.Stderr, err = testRunner.Cmd.StderrPipe()
	require.NoError(t, err, "failed to redirect stderr")
	return testRunner
}
