# ExposureLedger: zero runtime dependencies (Node 25 built-ins only), so nothing is installed,
# at build time or at run time. Secrets are passed only when the container runs:
#   docker build -t exposureledger .
#   docker run --rm -p 8000:8000 --env-file .env.docker exposureledger      (live; see .env.docker.example)
#   docker run --rm -p 8000:8000 -e SAMPLE_MODE=true exposureledger         (offline sample mode)
FROM node:25-slim

ENV PORT=8000
WORKDIR /app

# .dockerignore keeps .env*, logs/, output/ and .git out of the image.
COPY . .

# The source stays root-owned. The non-root "node" user from the base image may write
# logs/ and output/, and may create new folders in /app, but cannot edit the shipped code.
RUN mkdir -p logs output \
 && chown node:node /app /app/logs /app/output

USER node
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8000)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]

CMD ["node", "--experimental-transform-types", "--no-warnings", "src/server.ts"]
