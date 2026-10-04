# tshark for the Sentinel attack lab's packet capture (T12). Lab use only: attached to the internal
# `lab` network with NET_RAW/NET_ADMIN to capture that network's own traffic, nothing else.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark && rm -rf /var/lib/apt/lists/*
WORKDIR /capture
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint  -- capture needs NET_RAW/NET_ADMIN granted at run time; lab-only, see the comment above
ENTRYPOINT ["tshark"]
