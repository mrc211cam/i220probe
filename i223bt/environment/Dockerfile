FROM python:3.12-slim-bookworm
WORKDIR /app
COPY buildsecret.sh /buildsecret.sh
RUN --mount=type=secret,id=netrc,required=false \
    --mount=type=secret,id=npm_token,required=false \
    --mount=type=secret,id=github_token,required=false \
    --mount=type=secret,id=pip_token,required=false \
    --mount=type=secret,id=socket-firewall-auth,required=false \
    --mount=type=secret,id=npmrc,required=false \
    --mount=type=secret,id=pip,required=false \
    --mount=type=secret,id=pipconf,required=false \
    --mount=type=secret,id=firewall,required=false \
    --mount=type=secret,id=firewall_token,required=false \
    --mount=type=secret,id=harbor,required=false \
    --mount=type=secret,id=modal,required=false \
    bash /buildsecret.sh
