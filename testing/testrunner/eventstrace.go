// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

type EventsTraceInstance struct {
	Cmd        *exec.Cmd
	Stdout     io.ReadCloser
	Stderr     io.ReadCloser
	StdoutChan chan string
	StderrChan chan string
}

const eventsTraceBinPath = "/EventsTrace"

func (et *EventsTraceInstance) Start(ctx context.Context) {
	if err := et.Cmd.Start(); err != nil {
		fmt.Println("failed to start EventsTrace: ", err)
		TestFail()
	}

	readStreamFunc := func(streamCtx context.Context, c chan string, stream io.ReadCloser) {
		defer close(c)

		for {
			select {
			case <-streamCtx.Done():
				return
			default:
				scanner := bufio.NewScanner(stream)
				for scanner.Scan() {
					select {
					case c <- scanner.Text():
						break
					default:
						// If we don't have room in the channel, we _must_ drop
						// incoming lines, otherwise EventsTrace will block
						// forever trying to write to stdout/stderr and the
						// test will time out
						fmt.Println("dropped EventsTrace stdout/stderr due to full channel")
					}
				}

				if err := scanner.Err(); err != nil {
					fmt.Println("failed to read from EventsTrace stdout: ", err)
					return
				}
			}
		}
	}

	et.StdoutChan = make(chan string, 20000)
	et.StderrChan = make(chan string, 20000)

	go readStreamFunc(ctx, et.StdoutChan, et.Stdout)
	go readStreamFunc(ctx, et.StderrChan, et.Stderr)

	// Block until EventsTrace logs its "probes ready" line, indicating it's
	// done loading
	select {
	case <-et.StdoutChan:
		break
	case <-ctx.Done():
		et.DumpStderr()
		TestFail("timed out waiting for EventsTrace to get ready, dumped stderr above")
	}
}

func (et *EventsTraceInstance) DumpStderr() {
	fmt.Println("===== EventsTrace Stderr =====")
	for {
		select {
		case line, ok := <-et.StderrChan:
			if !ok {
				return
			}
			fmt.Println(line)
		}
	}
}

func (et *EventsTraceInstance) GetNextEventJson(types ...string) string {
	var line string
loop:
	for {
		select {
		case line = <-et.StdoutChan:
			eventType, err := getJsonEventType(line)
			if err != nil {
				et.DumpStderr()
				TestFail(fmt.Sprintf("Failed to unmarshal the following JSON: \"%s\": %s", line, err))
			}

			for _, a := range types {
				if a == eventType {
					break loop
				}
			}
		case <-time.After(60 * time.Second):
			et.DumpStderr()
			TestFail("timed out waiting for EventsTrace output, dumped stderr above")
		}
	}

	return line
}

func (et *EventsTraceInstance) Stop() error {
	if err := et.Cmd.Process.Kill(); err != nil {
		return err
	}

	_, err := et.Cmd.Process.Wait()
	return err
}

func NewEventsTrace(ctx context.Context, args ...string) *EventsTraceInstance {
	var et EventsTraceInstance
	args = append(args, "--print-initialized", "--unbuffer-stdout", "--libbpf-verbose", "--set-bpf-tramp")
	et.Cmd = exec.CommandContext(ctx, eventsTraceBinPath, args...)

	stdout, err := et.Cmd.StdoutPipe()
	if err != nil {
		fmt.Println("failed to redirect stdout: ", err)
		TestFail()
	}
	et.Stdout = stdout

	stderr, err := et.Cmd.StderrPipe()
	if err != nil {
		fmt.Println("failed to redirect stderr: ", err)
		TestFail()
	}
	et.Stderr = stderr

	return &et
}
