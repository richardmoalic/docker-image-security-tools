# ==============================================================================
# Stage 1: Downloader & Cryptographic Verifier
# ==============================================================================

#FROM sigstore/cosign@sha256:15a55db594c5955fcd9ca27f95158f71753cd07e3942dda3235961d569392cbc AS cosign_src
#FROM aquasecurity/trivy:v0.72.0@sha256:b81e075c68ad4b1a567e7b4d511e3b0493b0087ae708ff4dd607c497cde1daf6 AS trivy_src
#FROM anchore/syft:1.46.0@sha256:12446440ad4a4d932126ae8ec0468c6403bfae93190390418406fd603ec117bf AS syft_src
#FROM anchore/grype:v0.115.0@sha256:4cdb48fc7da281cfa953bc02c332e4f90bc254c88e4a7a2a53a7db3439966ee6 AS grype_src
#FROM google/osv-scanner:v2.4.0@sha256:b764ca99db6d85907fdf6208cb429b6de9b5846c00b283deababeabfc5feb80c AS osv_src
#FROM openvex/vexctl:c613023a69ce990a54c25c2f5e69d5d78285927f@sha256:ae6e75bb80b9b77b660c779480e0864755fde1d7bd42afc4b64f077abc49b09f AS vexctl_src

FROM ghcr.io/sigstore/cosign/cosign:v2.4.1 AS cosign_src

FROM aquasec/trivy:0.72.0 AS trivy_src

FROM ghcr.io/anchore/syft:v1.46.0 AS syft_src

FROM ghcr.io/anchore/grype:v0.115.0 AS grype_src

FROM ghcr.io/google/osv-scanner:v2.4.0 AS osv_src

FROM ghcr.io/openvex/vexctl:c613023a69ce990a54c25c2f5e69d5d78285927f AS vexctl_src

FROM alpine:3.19 AS bootstrap

RUN apk add --no-cache curl tar

# Set strict version pins (managed by sync automation)

ARG SLSA_VERIFIER_VERSION=2.7.1
ARG SLSA_VERIFIER_SHA256_AMD64=946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339
ARG SLSA_VERIFIER_SHA256_ARM64=5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061
ARG WITNESS_VERSION=0.12.0

ARG TARGETARCH
WORKDIR /downloads

RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    curl -fsSL "https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/witness_${WITNESS_VERSION}_linux_${ARCH}.tar.gz" -o witness.tar.gz && \
    tar -xzf witness.tar.gz witness && \
    chmod +x witness && \
    mv witness /usr/local/bin/witness && \
    rm witness.tar.gz

# 2. SLSA-Verifier Download
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    curl -fsSL "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-${ARCH}" -o /usr/local/bin/slsa-verifier && \
    chmod +x /usr/local/bin/slsa-verifier

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
# Stage 4 - Clean Artifacts Export (Add this at the end of your Dockerfile)
# ==============================================================================
FROM scratch AS artifacts
COPY --from=runtime /artifacts /

# Secure non-root user execution boundary
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/trivy"]

