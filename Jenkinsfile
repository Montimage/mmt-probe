pipeline {
    agent {
        docker {
            image 'ubuntu'
            args '-u root:sudo -v $HOME/workspace/mmt-probe:/mmt-probe -v $HOME/workspace/mmt-sdk:/mmt-sdk && -v $HOME/workspace/mmt-security:/mmt-security'
        }
    }
    stages {
        stage("setup_enviroment") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'apt-get update -y'
                sh 'apt-get install -y git build-essential gcc cmake make gdb'
                sh 'apt-get install -y software-properties-common'
                sh 'apt-get install -y build-essential'
                sh 'add-apt-repository -y ppa:ubuntu-toolchain-r/test'
                sh 'apt-get update -y'
                sh 'apt-get install -y gcc-4.9 g++-4.9 cpp-4.9'
                sh 'cd /usr/bin && rm gcc g++ cpp && ln -s gcc-4.9 gcc && ln -s g++-4.9 g++ && ln -s cpp-4.9 cpp && gcc -v'                
            }
        }

        stage("install_dependencies") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'apt-get install -y libpcap-dev libconfuse-dev libxml2-dev'
                echo 'Installing hiredis'
                sh 'rm -rf hiredis/'
                sh 'git clone https://github.com/redis/hiredis.git'
                sh 'cd hiredis/ && make && make install && ldconfig && cd ..'
                echo 'Installing librdkafka'
                sh 'apt-get install -y libsasl2-dev libssl-dev python'
                sh 'rm -rf librdkafka/'
                sh 'git clone https://github.com/edenhill/librdkafka.git'
                sh 'cd librdkafka/ && ./configure && make && make install && ldconfig && cd ..'
            }
        }
        stage("install_dpi") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'dpkg -i /mmt-sdk/sdk/*.deb'
                sh 'ldconfig'
            }
        }

        stage("install_security") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'dpkg -i /mmt-security/*.deb'
                sh 'ldconfig'
            }
        }

        stage("compile_mmt_probe") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'cd /mmt-probe/ && make PCAP=1'
            }
        }

        stage("test_mmt_probe") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'Test PROBE'
                // sh 'cd /mmt-probe/ && make test PCAP=1'
            }
        }

        stage("create_deb_mmt_probe") {
            steps {
                bitbucketStatusNotify(buildState: 'INPROGRESS')
                sh 'Create a installation file for mmt-probe'
                // sh 'cd /mmt-probe/ && make test PCAP=1'
            }
        }
    }
    post {
        success {
            echo 'Do something when it is successful'
            bitbucketStatusNotify(buildState: 'SUCCESSFUL')
        }
        failure {
            echo 'Do something when it is failed'
            bitbucketStatusNotify(buildState: 'FAILED')
        }
    }

}