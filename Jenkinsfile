import groovy.transform.Field;

// todo: remove once toolchain is updated in build vm
def authGoogleCloud()
{
    def isDone = false
    // Try to auth right away to avoid repeatedly running vault, etc
    try
    {
        sh "gcloud auth activate-service-account --key-file /tmp/service_account.json"
        isDone = true
    }
    catch(Exception e)
    {
        // Looks like we need to go through the full process
    }

    if (isDone)
    {
        return
    }

    // Make sure we have the python bits we need
    try
    {
        sh "python2.7 -m pip install google_compute_engine"
    }
    catch (Exception err)
    {
        printLog "Failed to install google_compute_engine [ $err ]"
    }

    retry(5)
    {
        // Auth the service account
        sh "sudo rm -f /tmp/service_account.json"
        retVal = sh returnStatus: true, script: "vault read -field=value secret/gce/elastic-security-dev/service-account/endgame-ci > /tmp/service_account.json 2> /dev/null"
        if (0 != retVal)
        {
            // If there's an error, the token likely expired, so get a new one
            NEW_VAULT_TOKEN = sh(script: 'vault write -address=$VAULT_ADDR -field=token auth/approle/login role_id=$VAULT_ROLE_ID secret_id=$VAULT_SECRET_ID', returnStdout: true)
            // Need to override the original VAULT_TOKEN.
            // Setting VAULT_TOKEN or env.VAULT_TOKEN doesn't override the original
            withEnv(["VAULT_TOKEN=${NEW_VAULT_TOKEN}"])
            {
                sh 'vault read -field=value secret/gce/elastic-security-dev/service-account/endgame-ci > /tmp/service_account.json'
            }
        }

        sh "chmod 400 /tmp/service_account.json"


        def gRet = sh returnStatus: true, script: "gcloud auth activate-service-account --key-file /tmp/service_account.json"

        if (0 != gRet)
        {
            // Use the alternate way in case gcloud isn't installed (Amazon ARM, etc)

            // Best effort install if python3 isn't there
            def pyRet = sh returnStatus: true, script: "python3 --version"
            if (0 != pyRet)
            {
                def pyIn = sh returnStatus: true, script: "sudo yum -y install python3"
                if (0 != pyIn)
                {
                    sh returnStatus: true, script: "sudo apt-get -y install python3"
                }
            }

            sh "sudo python3 -m pip install --upgrade pip"
            sh "sudo python3 -m pip install gsutil"

            // Create answers to all the questions
            sh "touch /tmp/answers.txt && chmod 600 /tmp/answers.txt"
            sh "echo /tmp/service_account.json > /tmp/answers.txt"
            sh "echo elastic-security-dev >> /tmp/answers.txt"
            sh "chmod 400 /tmp/answers.txt"

            // Remove any boto backup file since it will cause an error
            sh "rm -f /var/lib/jenkins/.boto.bak"

            // Authenticate
            sh "cat /tmp/answers.txt | gsutil config -e"
        }
    }
}

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

    // TODO: Remove once linux build VM is updated
    authGoogleCloud()
    sh "gsutil cp gs://endpoint-dev-artifacts/endpoint-toolchain/20211210-1318/install-opt-endpoint-dev-dev-20211210-1318.sh ."
    sh "chmod +x install-opt-endpoint-dev-dev-20211210-1318.sh"
    sh "yes yes | sudo ./install-opt-endpoint-dev-dev-20211210-1318.sh"

    def kernel_version = sh(script: 'uname -r', returnStdout: true)
    println "Building ebpf for arch ${arch} - kernel ${kernel_version}"

    // Build the binaries
    withEnv(["PATH=${path}:$PATH",
        "AR=${arpath}",
        "CPATH=${cpath}",
        "MAKESYSPATH=/opt/endpoint-dev/dev/toolchain/share/mk"])
    {
        dir("build-${arch}") {
            sh "cmake -DUSE_BUILTIN_VMLINUX=True -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ .."
            sh "make"
            sh "cp target/ebpf/*.bpf.o target/test"

            // Stash the tests
            stash includes: "target/test/**", name: "tests-${arch}"

            // Copy and archive the build dir
            sh "mkdir -p target-archive/${arch}"
            sh "cp -r target target-archive/${arch}"
            sh "mkdir -p target-archive/${arch}/_debug"
            sh "cp non-GPL/EventsTrace/EventsTrace target-archive/${arch}/_debug/EventsTrace"
            archiveArtifacts "target-archive/**"
        }

        // Clean the build
        sh "rm -Rf build-${arch}"
    }
}

pipeline {
    agent { label 'linux-builder' }

    environment
    {
        // TODO: Remove once linux build VM is updated
        // these are used to download the toolchain
        VAULT_ROLE_ID = credentials('vault-role-id')
        VAULT_ADDR = credentials('vault-addr')
        VAULT_SECRET_ID = credentials('vault-secret-id')
    }

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

