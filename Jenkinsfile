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
    "amazon-x86_64",
    "centos-8",
    "ubuntu-16.04",
    "ubuntu-18.04",
    "ubuntu-1804-desktop",
    "ubuntu-20.04",
    "ubuntu-20.04-secureboot",
    "rhel-7",
    "rhel-8",
]

///
/// Linux AARCH64 (ARM) node labels
///
@Field def LINUX_TEST_NODES_AARCH64 = [
    "amazon-arm",
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

            println "Running tests on ${machine_name} for arch ${arch}"

            try
            {
                // Unstash the test files
                unstash("tests-${arch}")

                def testBinaries = findFiles(glob: 'build/test/*Test')

                dir("build/test")
                {
                    sh "ls -al"
                    for (test in testBinaries)
                    {
                        println "Running test binary: ${test.name}"

                        def test_result_file = "${test.name}-result.xml"
                        def test_output_file = "test-output-${machine_name}-${test.name}.txt"

                        // Run the test binary
                        sh "sudo ./${test.name} --gtest_output=xml:${test_result_file} > ${test_output_file} 2>&1"

                        // Store the test results
                        junit keepLongStdio: true, testResults: "${test_result_file}"

                        // Archive the output
                        archiveArtifacts test_output_file
                        archiveArtifacts test_result_file
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

    // TODO: Uncomment once aarch64 files are built and
    // stashed separately from x64
    //linux_machines["aarch64"] = LINUX_TEST_NODES_AARCH64.clone()

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

    if (arch == "aarch64")
    {
        cpath = "/opt/endpoint-dev/dev/sysroot/aarch64-linux-gnu/usr/include"
    }

    println "Building ebpf for arch ${arch}"

    // Build the binaries
    withEnv(["PATH=/opt/endpoint-dev/dev/toolchain/bin:$PATH",
        "CPATH=${cpath}",
        "MAKESYSPATH=/opt/endpoint-dev/dev/toolchain/share/mk"])
    {
        sh "./build_lib.sh"

        // Copy the TcFilter.bpf.o file into the test dir
        sh "cp build/ebpf/TcFilter.bpf.o build/test"

        // Stash the tests
        stash includes: "build/test/**", name: "tests-${arch}"

        // Copy and archive the build dir
        sh "cp -r build build-${arch}"
        archiveArtifacts "build-${arch}/**"

        // Clean the build
        sh "./clean.sh"
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

                    /*
                    println "Building aarch64 ebpf"

                    // Build the aarch64 binaries
                    withEnv(["PATH=/opt/endpoint-dev/dev/toolchain/bin:$PATH",
                        "CPATH=/opt/endpoint-dev/dev/sysroot/aarch64-linux-gnu/usr/include",
                        "MAKESYSPATH=/opt/endpoint-dev/dev/toolchain/share/mk"])
                    {
                        sh "./build_lib.sh"

                        // Copy the TcFilter.bpf.o file into the test dir
                        sh "cp build/test/TcFilter.bpf.o build/test"

                        // Stash the aarch64 tests
                        stash includes: "build/test/**", name: "tests-aarch64"

                        // Copy and archive the build dir
                        sh "cp -r build build-aarch64"
                        archiveArtifacts "./build-aarch64/**"
                    }
                    */
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
