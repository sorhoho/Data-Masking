FROM openpolicyagent/opa:v1.4.2-rootless

COPY policy.rego      /policies/policy.rego
COPY opa-config.yaml  /policies/opa-config.yaml

EXPOSE 8181

# rootless image has no shell; use exec form directly.
# --addr 0.0.0.0:8181 so Kong can reach OPA across the Docker network.
# Bundle polling (15-60 s) handles the case where admin-service isn't ready yet.
CMD ["run", "--server", "--addr", "0.0.0.0:8181", "--log-level", "info",
     "--v0-compatible", "--config-file", "/policies/opa-config.yaml",
     "/policies/policy.rego"]
