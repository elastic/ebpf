import groovy.transform.Field;

// Run the job at various times for various important branches
def getCronString()
{
    if (env.BRANCH_NAME == "main")
    {
        // Run main once per day (12am UTC)
        return '0 0 * * *'
    }
    else
    {
        return ''
    }
}


// Get the cron string for the triggers section
def cronString = getCronString()

///
/// Linux x64 node labels
///
@Field def LINUX_TEST_NODES_X64 = [
//    "amazon-x86_64", TODO: fix the tests on al2, see https://github.com/elastic/ebpf/issues/34
    "centos-8",
    "ubuntu-20.04",
    "ubuntu-20.04-secureboot",
    "rhel-8",
]

///
/// Linux AARCH64 (ARM) node labels
///
@Field def LINUX_TEST_NODES_AARCH64 = [
//    "amazon-arm", TODO: fix the tests on al2, see https://github.com/elastic/ebpf/issues/34
    "centos-8-arm",
    "ubuntu-1804-arm",
]

///
/// Returns a test closure for an architecture and machine_name
///
def generateTestClosure(arch, machine_name)
{
    return {
        node(machine_name)
        {
            // Everything within node() gets run on the target machine
            def kernel_version = sh(script: 'uname -r', returnStdout: true)
            println "Running tests on ${machine_name} for arch ${arch} and kernel ${kernel_version}"

            // Make sure the BPF filesystem is mounted
            sh "sudo mount bpffs /sys/fs/bpf -t bpf || true"

            try
            {
                // Unstash the test files
                unstash("tests-${arch}")

                def testBinaries = findFiles(glob: 'target/test/*Tests')
                dir("target/test")
                {
                    for (test in testBinaries)
                    {
                        println "Running test binary: ${test.name}"

                        def return_val = -1
                        def test_result_file = "${test.name}-${arch}-${machine_name}-result.xml"
                        def test_output_file = "test-output-${arch}-${machine_name}-${test.name}.txt"
                        def run_script = "sudo ./${test.name} --gtest_output=xml:${test_result_file} > ${test_output_file} 2>&1"

                        // Run the test binary
                        return_val = sh returnStatus: true, script: run_script

                        if (0 != return_val)
                        {
                            // A return code of 1 means the gtest had failures, otherwise it's likely a crash
                            if (1 == return_val)
                            {
                                println "Failed tests running ${test.name} for arch ${arch} on ${machine_name}"
                            }
                            else
                            {
                                // Try to archive the output
                                archiveArtifacts allowEmptyArchive: true, artifacts: test_output_file
                                // Throw an error
                                error("Test file ${test.name} likely crashed on ${machine_name} with arch ${arch}")
                            }
                        }

                        // Archive the output
                        archiveArtifacts test_output_file

                        // Store the test results
                        junit keepLongStdio: true, testResults: "${test_result_file}"
                    }
                }
            }
            catch(err)
            {
                error("Caught exception running tests on ${machine_name} for arch ${arch}: [${err}]")
            }
        }
    }
}

///
/// Function returns a list of test closures
///
def getTestClosures()
{
    def test_closures = [:]

    def linux_machines = ["x64": [:], "aarch64": [:]]

    linux_machines["x64"]     = LINUX_TEST_NODES_X64.clone()
    linux_machines["aarch64"] = LINUX_TEST_NODES_AARCH64.clone()

    linux_machines.each { arch, machines ->
        machines.each { machine_name ->

            // Get the test closure
            closure = generateTestClosure(arch, machine_name)

            // Add it to the list of closures
            test_closures[machine_name] = closure
        }
    }

    return test_closures
}

def buildAndStash(arch)
{
    def cpath = "/opt/endpoint-dev/dev/sysroot/x86_64-linux-gnu/usr/include"
    def arpath = "/opt/endpoint-dev/dev/toolchain/bin/ar"
    def path  = "/opt/endpoint-dev/dev/toolchain/bin"

    if (arch == "aarch64")
    {
        cpath = "/opt/endpoint-dev/dev/sysroot/aarch64-linux-gnu/usr/include"
        arpath = "/opt/endpoint-dev/dev/toolchain/aarch64-linux-gnu/bin/ar"
        path = "/opt/endpoint-dev/dev/toolchain/aarch64-linux-gnu/bin:/opt/endpoint-dev/dev/toolchain/bin"
    }

    println "Building ebpf for arch ${arch}"

    // Build the binaries
    withEnv(["PATH=${path}:$PATH",
        "AR=${arpath}",
        "CPATH=${cpath}",
        "MAKESYSPATH=/opt/endpoint-dev/dev/toolchain/share/mk"])
    {
        dir("build-${arch}") {
            sh "cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ .."
            sh "make"
            sh "cp target/ebpf/*.bpf.o target/test"

            // Stash the tests
            stash includes: "target/test/**", name: "tests-${arch}"

            // Copy and archive the build dir
            sh "mkdir -p target-archive/${arch}"
            sh "cp -r target target-archive/${arch}"
            archiveArtifacts "target-archive/**"
        }


        // Clean the build
        sh "rm -Rf build-${arch}"
    }
}

pipeline {
    agent { label 'linux-builder' }

    options
    {
        buildDiscarder( logRotator(
                            numToKeepStr: "30",
                            artifactDaysToKeepStr: "10",
                            artifactNumToKeepStr: "10",
                            daysToKeepStr: "",
                            ))
    }

    triggers
    {
        cron("${cronString}")
    }

    parameters
    {
        booleanParam(
            defaultValue: true,
            description: "Whether to run tests",
            name: "ENABLE_TESTING"
        )
    }

    stages
    {
        stage('Build')
        {
            steps
            {
                script
                {
                    buildAndStash("x64")
                    buildAndStash("aarch64")
                }
            }
        }

        stage('Test')
        {
            when
            {
                expression { params.ENABLE_TESTING }
            }
            steps
            {
                script
                {
                    println "Test step"

                    // Generate the test closures to run
                    test_closures = getTestClosures()

                    // Run all test VMs in parallel
                    parallel test_closures
                }
            }
        }
    }
}
