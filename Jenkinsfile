@Library('jenkins-shared-library')_

// Helper which extracts a clean semver from `git describe`.
// Source-of-truth fallback is helm/Chart.yaml so chart + image versions stay
// in lockstep when no git tag has been cut yet.
def extractCleanVersion() {
    if (env.VERSION?.trim()) {
        return env.VERSION.trim()
    }

    def gitVersion = sh(script: "git describe --tags --always", returnStdout: true).trim()

    // Try to parse semver from git describe output (e.g. v0.0.9-3-gabcdef)
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

    return "0.0.9"
}

genericPod([
    "docker": "jfrog.kindredgroup.com/docker/docker:latest"
]) {
    def version
    def chartName = "kindred-mcp-gateway"
    def imageName = "agentgateway"
    def jfrogRegistry = "jfrog.kindredgroup.com/docker-dev"
    def jfrogRepositoryPrefix = "kindred/dde"
    def targetRepository = "${jfrogRepositoryPrefix}/${imageName}"
    def gitRevision

    stage('Checkout') {
        checkout([
            $class: 'GitSCM',
            branches: scm.branches,
            extensions: scm.extensions + [[$class: 'CloneOption', noTags: false, shallow: false]],
            userRemoteConfigs: scm.userRemoteConfigs
        ])
        version = extractCleanVersion()
        gitRevision = sh(script: "git rev-parse HEAD", returnStdout: true).trim()

        echo "==================================="
        echo "Chart version: ${version}"
        echo "Image tag:     v${version}"
        echo "Git revision:  ${gitRevision}"
        echo "Target image:  ${jfrogRegistry}/${targetRepository}:v${version}"
        echo "==================================="

        env.VERSION = version
    }

    stage('Build & Push Docker Image') {
        container('docker') {
            def imageTag = "v${version}"
            def targetImage = "${jfrogRegistry}/${targetRepository}:${imageTag}"

            echo "Building image from Dockerfile:"
            echo "  target:       ${targetImage}"
            echo "  --build-arg:  VERSION=${version}"
            echo "  --build-arg:  GIT_REVISION=${gitRevision}"

            docker.withRegistry("https://${jfrogRegistry}", 'artifactory-docker-deploy') {
                // The multi-stage Dockerfile targets linux/<TARGETARCH>. Jenkins
                // agents are amd64; cross-arch builds belong in a separate
                // buildx-enabled stage if/when needed.
                def img = docker.build(
                    targetImage,
                    "--build-arg VERSION=${version} --build-arg GIT_REVISION=${gitRevision} ."
                )
                img.push(imageTag)
                if (env.BRANCH_NAME == 'master') {
                    img.push('latest')
                    echo "Also pushed: ${jfrogRegistry}/${targetRepository}:latest"
                }
            }
        }
    }

    stage('Helm Package And Publish') {
        container('docker') {
            echo "Packaging Helm chart version: ${version}"

            sh 'apk add --no-cache curl tar sed'
            sh 'curl -fsSL https://get.helm.sh/helm-v3.15.3-linux-amd64.tar.gz | tar xz && mv linux-amd64/helm /usr/local/bin/helm && rm -rf linux-amd64'

            // Bake the JFrog image reference into values.yaml before packaging.
            sh """
                sed -i 's|^  registry:.*|  registry: ${jfrogRegistry}|' helm/values.yaml
                sed -i 's|^  repository:.*|  repository: ${targetRepository}|' helm/values.yaml
                sed -i 's|^  tag:.*|  tag: v${version}|' helm/values.yaml
            """

            // Vendor any subchart dependencies into helm/charts/ so the .tgz is
            // self-contained. No-op if there are no `dependencies:` declared.
            sh "helm dependency update helm"

            sh "helm package --app-version v${version} --version ${version} helm"

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
                    git push https://\${GIT_USER}:\${GIT_PASSWORD}@bitbucket.kindredgroup.com/bitbucket/scm/dde/kindred-mcp-gateway.git v${version} || echo "Tag already pushed"
                """
            }
        } else {
            echo "Skipping tag — not on master branch (current: ${env.BRANCH_NAME})"
        }
    }

    echo "==================================="
    echo "Build complete:"
    echo "  Image: ${jfrogRegistry}/${targetRepository}:v${version}"
    echo "  Helm:  ${chartName}-${version}"
    echo "==================================="
}
