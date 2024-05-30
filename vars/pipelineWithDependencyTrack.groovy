def call(Map params = [:]) {
    pipeline {
        agent any
        environment {
            DTRACK_API_KEY = params.get('DTRACK_API_KEY', 'odt_8FSqAZ7mXKRxzUETSnrnlf6do1HPBhOc')
            DTRACK_URL = params.get('DTRACK_URL', 'http://192.168.1.6:31511')
            PROJECT_NAME = params.get('PROJECT_NAME', 'java')
            version = params.get('version', 'Master')
        }
        stages {
            stage('Install jq') {
                steps {
                    sh 'apt-get update && apt-get install -y jq'
                }
            }
            stage('Clone the repo') {
                steps {
                    git params.get('repoUrl', 'https://github.com/Hassan-Eid-Hassan/java')
                }
            }
            stage('Generate BOM and Upload to Dependency-Track') {
                steps {
                    script {
                         sh """
                        whoami
                        echo "repo cloned"
                        curl -LO https://github.com/openclarity/kubeclarity/releases/download/v2.23.1/kubeclarity-cli-2.23.1-linux-amd64.tar.gz && tar -xzvf kubeclarity-cli-2.23.1-linux-amd64.tar.gz
                         ./kubeclarity-cli analyze ./ --input-type dir -o ${PROJECT_NAME}.sbom
                        echo "kubeclarity is installed"
                        """
                    }
                }
            }
            stage('Upload to Dependency-Track') {
                steps {
                    script {
                         sh '''
                        curl -k -X "POST" "${DTRACK_URL}/api/v1/bom" -H "Content-Type: multipart/form-data" -H "X-API-Key: ${DTRACK_API_KEY}" -F "autoCreate=true" -F "projectName=${PROJECT_NAME}" -F "projectVersion=${version}" -F "bom=@${PROJECT_NAME}.sbom"
                         '''
                    }
                }
            }
            stage('Check Vulnerabilities') {
                steps {
                    script {
                        def projectUuid = sh(script: """ curl -s -X "GET" -H "X-API-Key: ${DTRACK_API_KEY}" -H "Accept: application/json" "${DTRACK_URL}/api/v1/project/lookup?name=${PROJECT_NAME}&version=${version}" | jq -r .uuid """, returnStdout: true).trim()
                        sh """
                            echo UUID is ${projectUuid} 
                        """
                        def criticalCount = sh(script: """ curl -s -X "GET" -H "X-API-Key: ${DTRACK_API_KEY}" "${DTRACK_URL}/api/v1/vulnerability/project/${projectUuid}"| grep -o "CRITICAL" |wc -l """, returnStdout: true).trim()
                        sh """
                            echo "done critical count is  ${criticalCount} "
                        """
                        if (criticalCount.toInteger() >= 2) {
                            error("Pipeline failed due to ${criticalCount} critical vulnerabilities.")
                        } else {
                            echo "Pipeline passed with ${criticalCount} critical vulnerabilities."
                        }
                    }
                }
            }
        }
    }
}
