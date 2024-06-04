def call(Map config = [:]) { // Allow for configuration parameters
    node {
        withEnv([
            "DTRACK_API_KEY=${config.get('DTRACK_API_KEY', 'default_api_key')}",
            "DTRACK_URL=${config.get('DTRACK_URL', 'http://default-url')}",
            "PROJECT_NAME=${config.get('PROJECT_NAME', 'default_project')}",
            "VERSION=${config.get('VERSION', 'default_version')}",
            "REQUIREMENT_COUNT=${config.get('requirement_count', '2')}"
        ]) {
            stage('Install jq') {
                sh 'apt-get update && apt-get install -y jq'
            }
            stage('Clone the repo') {
                git url: config.get('repoUrl', 'https://github.com/default/repo')
            }
            stage('Generate BOM and Upload to Dependency-Track') {
                script {
                    sh """
                        whoami
                        echo "Repo cloned"
                        curl -LO https://github.com/openclarity/kubeclarity/releases/download/v2.23.1/kubeclarity-cli-2.23.1-linux-amd64.tar.gz
                        tar -xzvf kubeclarity-cli-2.23.1-linux-amd64.tar.gz
                        ./kubeclarity-cli analyze ./ --input-type dir -o ${env.PROJECT_NAME}.sbom
                        echo "kubeclarity is installed"
                    """
                }
            }
            stage('Upload to Dependency-Track') {
                script {
                    sh """
                        curl -k -X "POST" "${env.DTRACK_URL}/api/v1/bom" \
                        -H "Content-Type: multipart/form-data" \
                        -H "X-API-Key: ${env.DTRACK_API_KEY}" \
                        -F "autoCreate=true" \
                        -F "projectName=${env.PROJECT_NAME}" \
                        -F "projectVersion=${env.VERSION}" \
                        -F "bom=@${env.PROJECT_NAME}.sbom"
                    """
                }
            }
            stage('Check Vulnerabilities') {
                script {
                    def projectUuid = sh(script: """
                        curl -s -X "GET" -H "X-API-Key: ${env.DTRACK_API_KEY}" \
                        -H "Accept: application/json" \
                        "${env.DTRACK_URL}/api/v1/project/lookup?name=${env.PROJECT_NAME}&version=${env.VERSION}" | jq -r .uuid
                    """, returnStdout: true).trim()
                    
                    echo "UUID is ${projectUuid}"
                    
                    def criticalCount = sh(script: """
                        curl -s -X "GET" -H "X-API-Key: ${env.DTRACK_API_KEY}" \
                        "${env.DTRACK_URL}/api/v1/vulnerability/project/${projectUuid}" | grep -o "CRITICAL" | wc -l
                    """, returnStdout: true).trim()
                    
                    echo "Critical count is ${criticalCount}"
                    
                    if (criticalCount.toInteger() >= env.REQUIREMENT_COUNT.toInteger()) {
                        error("Pipeline failed due to ${criticalCount} critical vulnerabilities.")
                    } else {
                        echo "Pipeline passed with ${criticalCount} critical vulnerabilities."
                    }
                }
            }
        }
    }
}
