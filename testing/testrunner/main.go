// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

package main

func main() {
	RunTest(TestForkExit, "--process-fork")
	RunTest(TestForkExec, "--process-fork", "--process-exec")
	RunTest(TestSetuid, "--process-setuid")
	RunTest(TestSetgid, "--process-setgid")
	RunTest(TestFileCreate, "--file-create")
	RunTest(TestFileDelete, "--file-delete")
	RunTest(TestFileRename, "--file-rename")
	RunTest(TestFileCreateContainer, "--file-create")
	RunTest(TestFileRenameContainer, "--file-rename")
	RunTest(TestFileDeleteContainer, "--file-delete")

	AllTestsPassed()
	PowerOff()
}
