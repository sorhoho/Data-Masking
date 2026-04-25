FROM kong:3.5

# Kong runs as non-root; switch to root only to copy files and fix ownership
USER root

RUN mkdir -p /kong/plugins

COPY kong.yml    /kong/kong.yml
COPY plugins/    /kong/plugins/

RUN chown -R kong:kong /kong

USER kong

ENV KONG_DATABASE=off
ENV KONG_DECLARATIVE_CONFIG=/kong/kong.yml
ENV KONG_PLUGINS=bundled
ENV KONG_PROXY_ACCESS_LOG=/dev/stdout
ENV KONG_PROXY_ERROR_LOG=/dev/stderr
ENV KONG_ADMIN_ACCESS_LOG=/dev/stdout
ENV KONG_ADMIN_ERROR_LOG=/dev/stderr
ENV KONG_ADMIN_LISTEN="0.0.0.0:8001"

# 8000 = proxy, 8001 = admin (internal only)
EXPOSE 8000 8001
