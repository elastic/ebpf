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
