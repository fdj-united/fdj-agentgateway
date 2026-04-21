@Library('jenkins-shared-library')_

// Helper to extract clean version from the git describe
static String extractCleanVersion(script) {
    if (script.env.VERSION?.trim()) {
        return script.env.VERSION.trim()
    }

    def gitVersion = script.sh(script: "git describe --tags --always", returnStdout: true).trim()

    def matcher = gitVersion =~ /^.*?(\d+)\.(\d+)\.(\d+)(?:-(\d+))?(?:-g[0-9a-f]+)?$/

    if (matcher.matches()) {
        def major = matcher.group(1).toInteger()
        def minor = matcher.group(2).toInteger()
        def patch = matcher.group(3).toInteger()
        def commitsAfterTag = matcher.group(4)

        if (commitsAfterTag) {
            patch = patch + 1
        }

        return "${major}.${minor}.${patch}"
    }

    def fallback = gitVersion =~ /(\d+\.\d+\.\d+)/
    if (fallback.find()) {
        return fallback.group(1)
    }

    return "0.0.0"
}

genericPod([
    "docker": "jfrog.kindredgroup.com/docker/docker:latest"
]) {
    def version
    def chartName = "agentgateway"
    def imageRegistry
    def imageRepository
    def imageTag

    stage('Checkout') {
        checkout([
            $class: 'GitSCM',
            branches: scm.branches,
            extensions: scm.extensions + [[$class: 'CloneOption', noTags: false, shallow: false]],
            userRemoteConfigs: scm.userRemoteConfigs
        ])
        version = extractCleanVersion(this)

        // Read the Docker image reference from image.properties
        def props = readProperties file: 'deploy-k8s/image.properties'
        imageRegistry = props.IMAGE_REGISTRY
        imageRepository = props.IMAGE_REPOSITORY
        imageTag = props.IMAGE_TAG

        echo "==================================="
        echo "Chart version: ${version}"
        echo "Docker image: ${imageRegistry}/${imageRepository}:${imageTag}"
        echo "==================================="

        env.VERSION = version
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

            sh "helm package --app-version ${version} --version ${version} helm"

            withCredentials([usernamePassword(
                credentialsId: 'artifactory-helm-deploy',
                usernameVariable: 'HELM_USER',
                passwordVariable: 'HELM_PASSWORD'
            )]) {
                sh """
                    curl -f -u \${HELM_USER}:\${HELM_PASSWORD} \
                         -T ${chartName}-${version}.tgz \
                         'https://jfrog.kindredgroup.com/artifactory/charts-dev/${chartName}-${version}.tgz'
                """
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
                    git push https://\${GIT_USER}:\${GIT_PASSWORD}@bitbucket.kindredgroup.com/bitbucket/scm/mcp/agentgateway.git v${version} || echo "Tag already pushed"
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
