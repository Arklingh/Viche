// zk_worker.js — Off-main-thread Groth16 witness calculation & proof generation.
//
// Running snarkjs.groth16.fullProve inside a Web Worker prevents UI thread
// stutter and frame drops during heavy witness calculation & BN254 arithmetic.

// snarkjs is loaded same-origin from the app's own bundle, never from a CDN:
// this worker runs `fullProve`, which consumes the voter's `secret` during
// witness generation, so the bytes doing that have to be bytes we shipped.
// See `public/vendor/VENDOR.md` for provenance and hashes. The leading "/" is
// deliberate — Trunk copies `public/` to the site root (see the
// `data-target-path="/"` comment in index.html), and this worker may be
// constructed from any route.
importScripts("/vendor/snarkjs.min.js");

self.onmessage = async (event) => {
    const { id, type, payload } = event.data;

    if (type === "GENERATE_PROOF") {
        try {
            const { input, wasmUrl, zkeyUrl } = payload;
            console.log("[ZK WebWorker] Starting off-thread Groth16 fullProve...");

            if (!self.snarkjs || !self.snarkjs.groth16) {
                throw new Error("snarkjs.groth16 is unavailable in Web Worker context");
            }

            const startTime = performance.now();
            const { proof, publicSignals } = await self.snarkjs.groth16.fullProve(
                input,
                wasmUrl,
                zkeyUrl
            );
            const durationMs = (performance.now() - startTime).toFixed(2);
            console.log(`[ZK WebWorker] Groth16 proof computed in ${durationMs}ms`);

            self.postMessage({
                id,
                type: "PROOF_SUCCESS",
                payload: { proof, publicSignals, durationMs }
            });
        } catch (error) {
            console.error("[ZK WebWorker] Error generating proof:", error);
            self.postMessage({
                id,
                type: "PROOF_ERROR",
                error: String(error?.message ?? error)
            });
        }
    }
};
