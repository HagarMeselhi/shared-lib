def call(Map config) {
    pipeline {
        agent any
        environment {
            DTRACK_API_KEY = config.DTRACK_API_KEY
            DTRACK_URL = config.DTRACK_URL
            PROJECT_NAME = config.PROJECT_NAME
            REPO1_DIR = config.REPO1_DIR
            REPO2_DIR = config.REPO2_DIR
        }
        stages {
            stage('Install dependencies') {
                steps {
                    sh 'rm -rf master develop'
                    sh 'apt-get update && apt-get install -y jq'
                }
            }
            stage('Clone the repo') {
                steps {
                    script {
                        dir("${REPO1_DIR}") {
                            git url: 'https://github.com/RowanWally/java.git', branch: 'master'
                        }
                        dir("${REPO2_DIR}") {
                            git url: 'https://github.com/RowanWally/java.git', branch: 'dev'
                        }
                    }
                }
            }
            stage('Install Kubeclarity CLI') {
                steps {
                    script {
                        sh '''
                        curl -LO https://github.com/openclarity/kubeclarity/releases/download/v2.23.1/kubeclarity-cli-2.23.1-linux-amd64.tar.gz && tar -xzvf kubeclarity-cli-2.23.1-linux-amd64.tar.gz
                        mv kubeclarity-cli /usr/bin/kubeclarity-cli
                        chmod +x /usr/bin/kubeclarity-cli
                        '''
                    }
                }
            }
            stage('Generate BOM using Kubeclarity') {
                steps {
                    script {
                        dir("${REPO1_DIR}") {
                            sh "kubeclarity-cli analyze ./ --input-type dir -o ${REPO1_DIR}.sbom"
                        }
                        dir("${REPO2_DIR}") {
                            sh "kubeclarity-cli analyze ./ --input-type dir -o ${REPO2_DIR}.sbom"
                        }
                    }
                }
            }
            stage('Upload BOM to Dependency-Track') {
                steps {
                    script {
                        dir("${REPO1_DIR}") {
                            sh '''
                            curl -k -X "POST" "${DTRACK_URL}/api/v1/bom" -H "Content-Type: multipart/form-data" -H "X-API-Key: ${DTRACK_API_KEY}" -F "autoCreate=true" -F "projectName=${PROJECT_NAME}" -F "projectVersion=${REPO1_DIR}" -F "bom=@${REPO1_DIR}.sbom"
                            '''
                        }
                        dir("${REPO2_DIR}") {
                            sh '''
                            curl -k -X "POST" "${DTRACK_URL}/api/v1/bom" -H "Content-Type: multipart/form-data" -H "X-API-Key: ${DTRACK_API_KEY}" -F "autoCreate=true" -F "projectName=${PROJECT_NAME}" -F "projectVersion=${REPO2_DIR}" -F "bom=@${REPO2_DIR}.sbom"
                            '''
                        }
                    }
                }
            }
            stage('Check Vulnerabilities') {
                steps {
                    script {
                        def getProjectUuid = { repoDir ->
                            sh(script: """curl -s -X "GET" -H "X-API-Key: ${DTRACK_API_KEY}" -H "Accept: application/json" "${DTRACK_URL}/api/v1/project/lookup?name=${PROJECT_NAME}&version=${repoDir}" | jq -r .uuid""", returnStdout: true).trim()
                        }
                        def getCount = { uuid, severity ->
                            sh(script: """curl -s -X "GET" -H "X-API-Key: ${DTRACK_API_KEY}" "${DTRACK_URL}/api/v1/vulnerability/project/${uuid}" | grep -o "${severity}" | wc -l""", returnStdout: true).trim().toInteger()
                        }

                        def projectUuid1 = getProjectUuid(REPO1_DIR)
                        def projectUuid2 = getProjectUuid(REPO2_DIR)
                        
                        def criticalCountMaster = getCount(projectUuid1, "CRITICAL")
                        def criticalCountDev = getCount(projectUuid2, "CRITICAL")
                        def highCountMaster = getCount(projectUuid1, "HIGH")
                        def highCountDev = getCount(projectUuid2, "HIGH")

                        if (criticalCountDev >= criticalCountMaster || highCountDev >= highCountMaster) {
                            error("Pipeline failed due to ${criticalCountDev} or ${highCountDev} which is more than the critical or High vulnerabilities in Master branch.")
                        } else {
                            echo "Pipeline passed with ${criticalCountDev} or ${highCountDev} which is less than or equal the critical vulnerabilities in Master branch."
                        }
                    }
                }
            }
        }
    }
}
