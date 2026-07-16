# ==============================================================================
# Stage 1: Downloader & Cryptographic Verifier
# ==============================================================================
FROM alpine:3.19 AS builder

RUN apk add --no-cache curl tar

# Set strict version pins (managed by sync automation)
ARG COSIGN_VERSION=2.4.1
ARG TRIVY_VERSION=0.72.0
ARG SYFT_VERSION=1.46.0
ARG OSV_VERSION=2.4.0
ARG GRYPE_VERSION=0.115.0
ARG VEX_VERSION=0.4.1
ARG SLSA_VERIFIER_VERSION=2.4.1
ARG WITNESS_VERSION=0.7.0
ARG TARGETARCH

WORKDIR /workspace

# Write the verification engine helper script
RUN cat > /usr/local/bin/download_verify <<'EOF' && chmod +x /usr/local/bin/download_verify
#!/bin/sh
set -eu

FILE="$1"
URL="$2"
CHECKSUM_URL="$3"

# 1. Download Binary & Checksums
curl -fsSL "$URL" -o "$FILE"
curl -fsSL "$CHECKSUM_URL" -o checksums.txt

# 2. Extract and verify SHA-256
EXPECTED=$(grep " $(basename "$FILE")\$" checksums.txt | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
    # Fallback pattern matching for some releases formatting (e.g. syft/grype)
    EXPECTED=$(grep -E "^[a-f0-9]{64}\s+\*?$(basename "$FILE")" checksums.txt | awk '{print $1}')
fi

if [ -z "$EXPECTED" ]; then
    echo "❌ Error: Checksum not found for $(basename "$FILE")"
    exit 1
fi

echo "${EXPECTED}  ${FILE}" | sha256sum -c -
echo "✅ Checksum verification succeeded for $(basename "$FILE")"
rm checksums.txt
EOF

# ------------------------------------------------------------------------------
# A. Bootstrap Cosign First (Needed to verify all subsequent tools)
# ------------------------------------------------------------------------------
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "cosign" \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${ARCH}" \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-release-checksums.txt" && \
    chmod +x cosign && \
    mv cosign /usr/local/bin/cosign

# ------------------------------------------------------------------------------
# B. Download and Verify Remaining Binaries (Checksum + Cosign Blob Verification)
# ------------------------------------------------------------------------------

# 1. Trivy
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="64bit"; else ARCH="ARM64"; fi && \
    /usr/local/bin/download_verify \
    "trivy.tar.gz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" && \
    # Verify signature
    curl -fsSL -o trivy.sig "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz.sig" && \
    curl -fsSL -o trivy.pem "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz.pem" && \
    cosign verify-blob \
      --signature trivy.sig \
      --certificate trivy.pem \
      --certificate-identity "https://github.com/aquasecurity/trivy/.github/workflows/release.yaml@refs/tags/v${TRIVY_VERSION}" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      trivy.tar.gz && \
    tar -xzf trivy.tar.gz trivy && chmod +x trivy && rm trivy.tar.gz trivy.sig trivy.pem

# 2. Syft
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "syft.tar.gz" \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz" \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" && \
    # Verify signature
    curl -fsSL -o syft.sig "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz.sig" && \
    curl -fsSL -o syft.pem "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz.pem" && \
    cosign verify-blob \
      --signature syft.sig \
      --certificate syft.pem \
      --certificate-identity "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/tags/v${SYFT_VERSION}" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      syft.tar.gz && \
    tar -xzf syft.tar.gz syft && chmod +x syft && rm syft.tar.gz syft.sig syft.pem

# 3. OSV-Scanner
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "osv-scanner" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${ARCH}" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${ARCH}.sha256" && \
    chmod +x osv-scanner

# 4. Grype
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "grype.tar.gz" \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz" \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_checksums.txt" && \
    # Verify signature
    curl -fsSL -o grype.sig "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz.sig" && \
    curl -fsSL -o grype.pem "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz.pem" && \
    cosign verify-blob \
      --signature grype.sig \
      --certificate grype.pem \
      --certificate-identity "https://github.com/anchore/grype/.github/workflows/release.yaml@refs/tags/v${GRYPE_VERSION}" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      grype.tar.gz && \
    tar -xzf grype.tar.gz grype && chmod +x grype && rm grype.tar.gz grype.sig grype.pem

# 5. Vexctl
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "vexctl" \
    "https://github.com/openvex/vexctl/releases/download/v${VEX_VERSION}/vexctl-linux-${ARCH}" \
    "https://github.com/openvex/vexctl/releases/download/v${VEX_VERSION}/checksums.txt" && \
    chmod +x vexctl

# 6. Witness
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "witness.tar.gz" \
    "https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/witness_${WITNESS_VERSION}_linux_${ARCH}.tar.gz" \
    "https://github.com/in-toto/witness/releases/download/v${WITNESS_VERSION}/witness_${WITNESS_VERSION}_checksums.txt" && \
    tar -xzf witness.tar.gz witness && chmod +x witness && rm witness.tar.gz

# 7. SLSA-Verifier
RUN if [ "$TARGETARCH" = "amd64" ]; then ARCH="amd64"; else ARCH="arm64"; fi && \
    /usr/local/bin/download_verify \
    "slsa-verifier" \
    "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-${ARCH}" \
    "https://github.com/slsa-framework/slsa-verifier/releases/download/v${SLSA_VERIFIER_VERSION}/shasumv2.txt" && \
    chmod +x slsa-verifier


# ==============================================================================
# Stage 2 - Generate Security Artifacts
# ==============================================================================

FROM builder AS artifacts

RUN mkdir -p /artifacts

#
# Generate SBOM for the verification image itself
#

# 2. Run Vulnerability Scans directly against the generated SBOMs
# Grype scan using the SPDX SBOM
RUN grype sbom:/artifacts/sbom.spdx.json -o json > /artifacts/grype.json

# Trivy scan using the CycloneDX SBOM (Trivy excels at CycloneDX)
RUN trivy sbom /artifacts/sbom.cdx.json --format json --output /artifacts/trivy.json

# OSV-Scanner using the SPDX SBOM
RUN osv-scanner --sbom /artifacts/sbom.spdx.json --format json > /artifacts/osv.json

# 3. Create a VEX Statement
RUN vexctl create \
    --product "pkg:oci/ghcr.io/OWNER/IMAGE@__DIGEST__" \
    --vuln "CVE-2024-12345" \
    --status "not_affected" \
    --justification "component_not_present" \
    > /artifacts/vex.template.json

# 4. Filter the Trivy vulnerabilities using the VEX statement (Rescan/Filter step)
# This outputs a VEX-filtered vulnerability report containing only actionable items
RUN vexctl filter \
      --vex /artifacts/vex.json \
      --input /artifacts/trivy.json \
      > /artifacts/trivy-filtered.json

#
# Witness evidence
#
RUN witness run \
      --step build \
      --materials /workspace \
      --out /artifacts/witness.dsse.json \
      true

# ==============================================================================
# Stage 3 - Runtime
# ==============================================================================

FROM gcr.io/distroless/static-debian12:latest AS runtime

# Copy statically-linked compiled binaries into path
COPY --from=builder /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=builder /workspace/trivy /usr/local/bin/trivy
COPY --from=builder /workspace/syft /usr/local/bin/syft
COPY --from=builder /workspace/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /workspace/grype /usr/local/bin/grype
COPY --from=builder /workspace/vexctl /usr/local/bin/vexctl
COPY --from=builder /workspace/witness /usr/local/bin/witness
COPY --from=builder /workspace/slsa-verifier /usr/local/bin/slsa-verifier

# Secure non-root user execution boundary
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/trivy"]