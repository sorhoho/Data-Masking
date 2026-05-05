FROM openpolicyagent/opa:1.16.1-debug

COPY policy.rego      /policies/policy.rego
COPY opa-config.yaml  /policies/opa-config.yaml

EXPOSE 8181

# Wait for admin-service before starting so the first bundle fetch succeeds.
# Policy uses `import rego.v1` (native OPA v1 syntax) — no --v0-compatible needed.
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["until wget -qO /dev/null http://admin-service:8888/health 2>/dev/null; do echo 'OPA: waiting for admin-service...'; sleep 2; done; exec /opa run --server --log-level info --config-file /policies/opa-config.yaml /policies/policy.rego"]
