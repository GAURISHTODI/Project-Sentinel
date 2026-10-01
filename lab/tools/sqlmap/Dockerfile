# sqlmap for the Sentinel attack lab. Lab use only: attached to the internal `lab` network,
# every invocation is guarded by lab/guard.sh so it can never target a real host.
FROM python:3.12-slim
RUN pip install --no-cache-dir sqlmap \
    && useradd --system --uid 10010 --create-home attacker
USER 10010
WORKDIR /home/attacker
ENTRYPOINT ["sqlmap"]
