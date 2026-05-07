FROM openpolicyagent/opa:v1.4.2-debug

COPY policy.rego      /policies/policy.rego
COPY opa-config.yaml  /policies/opa-config.yaml

EXPOSE 8181

# Wait for admin-service before starting so the first bundle fetch succeeds.
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["until wget -qO /dev/null http://admin-service:8888/health 2>/dev/null; do echo 'OPA: waiting for admin-service...'; sleep 2; done; exec /opa run --server --addr 0.0.0.0:8181 --log-level info --v0-compatible --config-file /policies/opa-config.yaml /policies/policy.rego"]
