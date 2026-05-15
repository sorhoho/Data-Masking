FROM openpolicyagent/opa:1.16.1-debug

COPY policy.rego      /policies/policy.rego
COPY opa-config.yaml  /policies/opa-config.yaml

EXPOSE 8181

ENV BUNDLE_SERVICE_URL=http://admin-service:8888

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["until wget -qO /dev/null ${BUNDLE_SERVICE_URL}/health 2>/dev/null; do echo 'OPA: waiting for bundle server...'; sleep 2; done; exec /opa run --server --addr 0.0.0.0:8181 --log-level info --config-file /policies/opa-config.yaml /policies/policy.rego"]
