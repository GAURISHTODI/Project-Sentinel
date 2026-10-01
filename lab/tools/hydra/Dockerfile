# THC-Hydra for the Sentinel attack lab. Lab use only: attached to the internal `lab` network,
# every invocation is guarded by lab/guard.sh so it can never target a real host.
FROM kalilinux/kali-rolling
RUN apt-get update \
    && apt-get install -y --no-install-recommends hydra \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10011 --create-home attacker
USER 10011
WORKDIR /home/attacker
ENTRYPOINT ["hydra"]
