# ==============================================================================
# Stage 1: Downloader & Cryptographic Verifier
# ==============================================================================

FROM ghcr.io/sigstore/cosign/cosign:v2.4.1 AS cosign_src

FROM aquasec/trivy:0.72.0 AS trivy_src

FROM ghcr.io/anchore/syft:v1.46.0 AS syft_src

FROM ghcr.io/anchore/grype:v0.115.0 AS grype_src

FROM ghcr.io/google/osv-scanner:v2.4.0 AS osv_src

FROM ghcr.io/openvex/vexctl:c613023a69ce990a54c25c2f5e69d5d78285927f AS vexctl_src

FROM alpine:3.19 AS bootstrap
COPY --from=cosign_src /ko-app/cosign /usr/local/bin/cosign

RUN apk add --no-cache curl tar ca-certificates

ARG SLSA_VERIFIER_VERSION=2.7.1
ARG SLSA_VERIFIER_SHA256_AMD64=946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339
ARG SLSA_VERIFIER_SHA256_ARM64=5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061
ARG WITNESS_VERSION=0.12.0

ARG TARGETARCH
WORKDIR /downloads


RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    FILE="witness_${WITNESS_VERSION}_linux_${ARCH}.tar.gz" && \
    curl -fsSLO "https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/${FILE}" && \
    curl -fsSLO "https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/witness_${WITNESS_VERSION}_checksums.txt" && \
    curl -fsSLO "https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/witness_${WITNESS_VERSION}_linux_${ARCH}.tar.gz.sigstore.json" && \
    \
    # Validate the SHA256 checksum 
    grep -E "[[:space:]]${FILE}$" witness_${WITNESS_VERSION}_checksums.txt > verification.txt && \
    sha256sum -c verification.txt && \
    \
    # Verify the signature via Cosign
    cosign verify-blob witness.tar.gz \
      --bundle witness.sigstore.json \
      --certificate-identity-regexp "^https://github.com/in-toto/witness/" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" && \
    \
    tar -xzf witness.tar.gz witness && \
    chmod +x witness && \
    mv witness /usr/local/bin/witness && \
    rm witness.tar.gz witness_checksums.txt witness.sigstore.json verification.txt /usr/local/bin/cosign


RUN if [ "$TARGETARCH" = "amd64" ]; then \
    ARCH="amd64"; EXPECTED_SHA="${SLSA_VERIFIER_SHA256_AMD64}"; \
    else \
      ARCH="arm64"; EXPECTED_SHA="${SLSA_VERIFIER_SHA256_ARM64}"; \
    fi && \
    curl -fsSL "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-${ARCH}" -o /usr/local/bin/slsa-verifier && \
    echo "${EXPECTED_SHA}  /usr/local/bin/slsa-verifier" > slsa.sha256 && \
    sha256sum -c slsa.sha256 && \
    chmod +x /usr/local/bin/slsa-verifier && \
    rm slsa.sha256

# ==============================================================================
# Stage 3 - Runtime
# ==============================================================================
FROM alpine:3.19 AS runtime
RUN mkdir -p /artifacts /workspace



# Copy statically-linked compiled binaries into path
COPY --from=cosign_src /ko-app/cosign /usr/local/bin/cosign
COPY --from=trivy_src /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=syft_src /syft /usr/local/bin/syft
COPY --from=grype_src /grype /usr/local/bin/grype
COPY --from=osv_src /osv-scanner /usr/local/bin/osv-scanner
COPY --from=vexctl_src /ko-app/vexctl /usr/local/bin/vexctl
COPY --from=bootstrap /usr/local/bin/witness /usr/local/bin/witness
COPY --from=bootstrap /usr/local/bin/slsa-verifier /usr/local/bin/slsa-verifier


RUN mkdir -p /artifacts

# Create template SBOMs
RUN syft dir:. -o spdx-json=/artifacts/sbom.spdx.json
RUN syft dir:. -o cyclonedx-json=/artifacts/sbom.cdx.json


# ==============================================================================
# Stage 4 - Clean Artifacts Export
# ==============================================================================
FROM scratch AS artifacts
COPY --from=runtime /artifacts /

# Secure non-root user execution boundary
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/trivy"]



