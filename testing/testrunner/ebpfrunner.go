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
	ctx        context.Context
	Cmd        *exec.Cmd
	Stdout     io.ReadCloser
	Stderr     io.ReadCloser
	StdoutChan chan string
	StderrChan chan string
	InitMsg    InitMsg
	t          *testing.T

	// in case of failure, we want to dump everything that EventTrace has done,
	// so track in one central place so we can dump on failure
	errBuff string
	outBuff string
}

func runStreamChannel(t *testing.T, sender chan string, buffer *bufio.Scanner) {
	go func() {
		for {
			for buffer.Scan() {
				line := buffer.Text()
				if len(line) > 0 {
					txt := strings.TrimSpace(line)
					if len(txt) > 0 {
						// TODO: we still risk a block here. Do we need a separate timeout?
						sender <- txt

					}
				}
			}
			if err := buffer.Err(); err != nil {
				t.Logf("scanner error: %s", err)
			}

		}
	}()
}

func (runner *Runner) Start() {
	err := runner.Cmd.Start()
	require.NoError(runner.t, err)
	stderrStream := bufio.NewScanner(NewContextReader(runner.ctx, runner.Stderr))
	stdoutStream := bufio.NewScanner(NewContextReader(runner.ctx, runner.Stdout))

	runStreamChannel(runner.t, runner.StdoutChan, stdoutStream)
	runStreamChannel(runner.t, runner.StderrChan, stderrStream)

	// we only care about stderr in failures;
	// run a channel that just appends it to our buffer
	go func() {
		for line := range runner.StderrChan {
			runner.errBuff = fmt.Sprintf("%s\n%s", runner.errBuff, line)
		}
	}()

	runner.t.Logf("Waiting for initial response from EventsTrace...")

	// run until we get the first log line
	// TODO: should we run this in a loop and verify the message?
	select {
	case <-runner.ctx.Done():
		runner.t.Fatalf("timed out while waiting for initial response from EventsTrace")
	case line := <-runner.StdoutChan:
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
		case line := <-runner.StdoutChan:
			// log stdout
			runner.outBuff = fmt.Sprintf("%s\n%s", runner.outBuff, line)

			var resp baseEvent
			err := json.Unmarshal([]byte(line), &resp)
			require.NoError(runner.t, err, "error unmarshaling event_type from stdout. stderr: \n", runner.errBuff)
			for _, evtType := range types {
				if evtType == resp.EventType {
					return line
				}
			}
		}
	}
}

func (runner *Runner) UnmarshalNextEvent(t *testing.T, body any, types ...string) {
	line := runner.GetNextEventOut(types...)
	err := json.Unmarshal([]byte(line), &body)
	require.NoError(t, err, "error unmarshaling JSON for types %v", types)
}

func (runner *Runner) Stop() {
	close(runner.StderrChan)
	close(runner.StdoutChan)
	err := runner.Cmd.Process.Kill()
	require.NoError(runner.t, err)

	_, err = runner.Cmd.Process.Wait()
	require.NoError(runner.t, err)
}

func (runner *Runner) Dump() {
	runner.t.Logf("STDOUT:\n %s \n STDERR: \n%s", runner.outBuff, runner.errBuff)
}

func NewEbpfRunner(ctx context.Context, t *testing.T, args ...string) *Runner {
	testRunner := &Runner{
		ctx:        ctx,
		StdoutChan: make(chan string, 100),
		StderrChan: make(chan string, 100),
		t:          t,
	}
	binPath := "../../artifacts-x86_64/non-GPL/Events/EventsTrace/EventsTrace"
	args = append(args, "--print-features-on-init", "--unbuffer-stdout", "--libbpf-verbose")
	testRunner.Cmd = exec.CommandContext(ctx, binPath, args...)

	var err error
	testRunner.Stdout, err = testRunner.Cmd.StdoutPipe()
	require.NoError(t, err, "failed to redirect stdout")

	testRunner.Stderr, err = testRunner.Cmd.StderrPipe()
	require.NoError(t, err, "failed to redirect stderr")
	return testRunner
}
