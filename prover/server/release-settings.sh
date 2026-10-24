#!/bin/sh
# Prints the prover image build settings, run from the building repository root.
set -eu
# shellcheck source=/dev/null
. "$(dirname "$0")/release-build.env"
echo "goamd64=$PROVER_RELEASE_GOAMD64"
echo "pgo=$PROVER_RELEASE_PGO"
# An extension repository builds its own checkout.
if [ -f prover/go.mod ]; then
    echo "extension_ref=$(git rev-parse HEAD)"
    echo "extension_context=prover-extension=."
fi
