FROM quay.io/keycloak/keycloak:26.6.1

# Bake the realm config in so Keycloak auto-imports it on first boot.
# The import is idempotent – Keycloak skips it if the realm already exists.
COPY realm-config.json /opt/keycloak/data/import/realm-config.json

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--import-realm"]
