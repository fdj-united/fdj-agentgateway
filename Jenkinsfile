@Library('jenkins-shared-library')_

// Helper to extract clean version from git describe
def extractCleanVersion() {
    if (env.VERSION?.trim()) {
        return env.VERSION.trim()
    }

    def gitVersion = sh(script: "git describe --tags --always", returnStdout: true).trim()

    // Try to parse semver from git describe output (e.g. v0.0.1-3-gabcdef)
    def version = sh(
        script: """
            echo '${gitVersion}' | sed -n 's/^.*\\([0-9]\\+\\)\\.\\([0-9]\\+\\)\\.\\([0-9]\\+\\)\\(-\\([0-9]\\+\\)\\)\\?.*\$/\\1.\\2.\\3.\\5/p'
        """,
        returnStdout: true
    ).trim()

    if (version) {
        def parts = version.tokenize('.')
        def major = parts[0]
        def minor = parts[1]
        def patch = parts[2].toInteger()
        def commitsAfter = parts.size() > 3 ? parts[3] : ''

        if (commitsAfter) {
            patch = patch + 1
        }

        return "${major}.${minor}.${patch}"
    }

    // No tags found — fall back to version from Chart.yaml
    def chartVersion = sh(script: "grep '^version:' helm/Chart.yaml | awk '{print \$2}'", returnStdout: true).trim()
    if (chartVersion) {
        return chartVersion
    }

    return "0.0.1"
}

genericPod([
    "docker": "jfrog.kindredgroup.com/docker/docker:latest"
]) {
    def version
    def chartName = "kindred-mcp-gateway"
    def imageRegistry
    def imageRepository
    def imageTag
    def jfrogRegistry = "jfrog.kindredgroup.com/docker-dev"
    def jfrogRepositoryPrefix = "kindred/aie"

    stage('Checkout') {
        checkout([
            $class: 'GitSCM',
            branches: scm.branches,
            extensions: scm.extensions + [[$class: 'CloneOption', noTags: false, shallow: false]],
            userRemoteConfigs: scm.userRemoteConfigs
        ])
        version = extractCleanVersion()

        // Read the Docker image reference from image.properties
        def props = readProperties file: 'image.properties'
        imageRegistry = props.IMAGE_REGISTRY
        imageRepository = props.IMAGE_REPOSITORY
        imageTag = props.IMAGE_TAG

        echo "==================================="
        echo "Chart version: ${version}"
        echo "Source image:  ${imageRegistry}/${imageRepository}:${imageTag}"
        echo "==================================="

        env.VERSION = version
    }

    stage('Push Docker Image') {
        container('docker') {
            // Derive the image name from the source repository (e.g. "fdj-united/agentgateway" -> "agentgateway")
            def imageName = imageRepository.tokenize('/').last()
            def sourceImage = "${imageRegistry}/${imageRepository}:${imageTag}"
            def targetRepository = "${jfrogRepositoryPrefix}/${imageName}"
            def targetImage = "${jfrogRegistry}/${targetRepository}:${imageTag}"

            echo "Mirroring image:"
            echo "  source: ${sourceImage}"
            echo "  target: ${targetImage}"

            sh "docker pull ${sourceImage}"
            sh "docker tag ${sourceImage} ${targetImage}"

            docker.withRegistry("https://${jfrogRegistry}", 'artifactory-docker-deploy') {
                def image = docker.image(targetImage)
                image.push(imageTag)
                if (env.BRANCH_NAME == 'master') {
                    image.push('latest')
                    echo "Also pushed: ${jfrogRegistry}/${targetRepository}:latest"
                }
            }

            // Repoint the chart at the JFrog copy so the packaged values.yaml uses the mirrored image
            imageRegistry = jfrogRegistry
            imageRepository = targetRepository

            echo "Chart will reference: ${imageRegistry}/${imageRepository}:${imageTag}"
        }
    }

    stage('Helm Package And Publish') {
        container('docker') {
            echo "Packaging Helm chart version: ${version}"

            sh 'apk add --no-cache curl tar sed'
            sh 'curl -fsSL https://get.helm.sh/helm-v3.15.3-linux-amd64.tar.gz | tar xz && mv linux-amd64/helm /usr/local/bin/helm && rm -rf linux-amd64'

            // Bake the Docker image reference into values.yaml before packaging
            sh """
                sed -i 's|^  registry:.*|  registry: ${imageRegistry}|' helm/values.yaml
                sed -i 's|^  repository:.*|  repository: ${imageRepository}|' helm/values.yaml
                sed -i 's|^  tag:.*|  tag: ${imageTag}|' helm/values.yaml
            """

            // Fetch subchart dependencies (e.g. the upstream agentgateway control plane)
            // and vendor them into helm/charts/ so the published .tgz is self-contained.
            sh "helm dependency update helm"

            sh "helm package --app-version ${imageTag} --version ${version} helm"

            withCredentials([usernamePassword(
                credentialsId: 'artifactory-helm-deploy',
                usernameVariable: 'HELM_USER',
                passwordVariable: 'HELM_PASSWORD'
            )]) {
                def uploadStatus = sh(
                    script: """
                        curl -s -o /dev/null -w '%{http_code}' -u \${HELM_USER}:\${HELM_PASSWORD} \
                             -T ${chartName}-${version}.tgz \
                             'https://jfrog.kindredgroup.com/artifactory/charts-dev/${chartName}-${version}.tgz'
                    """,
                    returnStdout: true
                ).trim()

                if (uploadStatus == '201' || uploadStatus == '200') {
                    echo "Chart uploaded successfully (${uploadStatus})"
                } else if (uploadStatus == '409') {
                    echo "Chart version ${version} already exists in JFrog — skipping upload"
                } else {
                    error "Chart upload failed with HTTP ${uploadStatus}"
                }
            }

            sh "rm -f ${chartName}-${version}.tgz"
        }
    }

    stage('Tag Release') {
        if (env.BRANCH_NAME == 'master') {
            withCredentials([usernamePassword(
                credentialsId: 'bitbucket-admin',
                usernameVariable: 'GIT_USER',
                passwordVariable: 'GIT_PASSWORD'
            )]) {
                sh """
                    git config user.email "dummy.robobuild@kindredgroup.com"
                    git config user.name "Robo creating releases"
                    git tag -a v${version} -m "Release v${version}" || echo "Tag v${version} already exists, skipping"
                    git push https://\${GIT_USER}:\${GIT_PASSWORD}@bitbucket.kindredgroup.com/bitbucket/scm/mcp/kindred-mcp-gateway.git v${version} || echo "Tag already pushed"
                """
            }
        } else {
            echo "Skipping tag — not on master branch (current: ${env.BRANCH_NAME})"
        }
    }

    echo "==================================="
    echo "Build complete:"
    echo "  Image: ${imageRegistry}/${imageRepository}:${imageTag}"
    echo "  Helm: ${chartName}-${version}"
    echo "==================================="
}
