FROM openpolicyagent/opa:v1.4.2-rootless

COPY policy.rego      /policies/policy.rego
COPY opa-config.yaml  /policies/opa-config.yaml

EXPOSE 8181

CMD ["run", "--server", "--log-level", "info", "--v0-compatible", \
     "--config-file", "/policies/opa-config.yaml", "/policies/policy.rego"]
