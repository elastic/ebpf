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

func (et *EventsTraceInstance) Start() {
	if err := et.Cmd.Start(); err != nil {
		fmt.Println("failed to start EventsTrace: ", err)
		TestFail()
	}

	et.StdoutChan = make(chan string)
	go func() {
		scanner := bufio.NewScanner(et.Stdout)
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				fmt.Println("failed to read from EventsTrace stdout: ", err)
				return
			}
			et.StdoutChan <- scanner.Text()
		}
	}()

	et.StderrChan = make(chan string, 100)
	go func() {
		scanner := bufio.NewScanner(et.Stderr)
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				fmt.Println("failed to read from EventsTrace stderr: ", err)
				return
			}
			et.StderrChan <- scanner.Text()
		}
	}()

	// This timeout is long on purpose, when running without KVM on a system
	// under heavy load, it may actually take tens of seconds for EventsTrace
	// to start up
	select {
	case <-et.StdoutChan:
		break
	case <-time.After(60 * time.Second):
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
		case <-time.After(1 * time.Second):
			return
		}
	}
}

func (et *EventsTraceInstance) GetNextEventJson(types ...string) string {
	var line string
loop:
	for {
		select {
		case line = <-et.StdoutChan:
			eventType := getJsonEventType(line)

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

func NewEventsTrace(args ...string) *EventsTraceInstance {
	var et EventsTraceInstance
	args = append(args, "--print-initialized", "--unbuffer-stdout", "--libbpf-verbose", "--set-bpf-tramp")
	et.Cmd = exec.Command(eventsTraceBinPath, args...)

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
