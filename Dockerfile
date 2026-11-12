FROM python:3.12-slim
RUN useradd --system --home /app --uid 10001 gateway
WORKDIR /app
COPY pyproject.toml README.md ./
COPY acp_gateway ./acp_gateway
# acp-sdk is private: pass a read token as a BuildKit secret, never as a build arg
#   docker build --secret id=github_token,env=GH_READ_TOKEN -t acp-gateway:0.1.0 .
RUN --mount=type=secret,id=github_token \
    apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* && \
    git config --global url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/" && \
    pip install --no-cache-dir . && \
    git config --global --unset-all url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf && \
    apt-get purge -y git && apt-get autoremove -y
USER gateway
ENV ACP_GATEWAY_HOST=0.0.0.0 ACP_GATEWAY_PORT=8080
EXPOSE 8080
CMD ["python", "-m", "acp_gateway"]
