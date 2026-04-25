FROM openpolicyagent/opa:latest-rootless

COPY policy.rego /policies/policy.rego

EXPOSE 8181

CMD ["run", "--server", "--log-level", "info", "/policies/policy.rego"]
