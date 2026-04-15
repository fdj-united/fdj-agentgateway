#!/usr/bin/env bash
set -euo pipefail

ENV=${1:-local}   # usage: ./install.sh [local|production]

NAMESPACE="default"
VALUES_FILE="./values-${ENV}.yaml"

echo "Deploying agentgateway (standalone) for environment: ${ENV}"

helm upgrade -i kait-gateway ./chart \
  -n "${NAMESPACE}" \
  -f "${VALUES_FILE}"

echo ""
echo "Done. Check status with:"
echo "  kubectl get pods -n ${NAMESPACE}"
echo ""
echo "Forward ports with:"
echo "  kubectl port-forward svc/agentgateway 3001:3001 3002:3002 3003:3003 15000:15000 -n ${NAMESPACE}"
