// asset_cache.js — Browser Cache Storage API manager for Viche heavy ZK assets.
//
// Caches `vote.wasm` (~2MB) and `vote_final.zkey` (~5MB) in local browser cache
// (`viche-zk-v1`), eliminating redundant HTTP downloads across sessions.

const CACHE_NAME = "viche-zk-v1";
const ASSETS_TO_CACHE = [
    "/circuits/vote.wasm",
    "/circuits/vote_final.zkey"
];

// Pre-warm Cache Storage on initialization
async function initAssetCache() {
    if (!("caches" in window)) {
        console.warn("[AssetCache] Cache Storage API not supported in this browser environment.");
        return;
    }

    try {
        const cache = await caches.open(CACHE_NAME);
        for (const url of ASSETS_TO_CACHE) {
            const match = await cache.match(url);
            if (!match) {
                console.log(`[AssetCache] Pre-warming cache for ${url}...`);
                await cache.add(url);
                console.log(`[AssetCache] Successfully cached ${url}`);
            } else {
                console.log(`[AssetCache] Asset ${url} is already cached locally.`);
            }
        }
    } catch (err) {
        console.warn("[AssetCache] Cache pre-warming warning:", err);
    }
}

// Global helper to retrieve a cached blob URL or fallback to the original URL
window.__VICHE_GET_CACHED_ASSET = async function(url) {
    if (!("caches" in window)) return url;
    try {
        const cache = await caches.open(CACHE_NAME);
        const match = await cache.match(url);
        if (match) {
            const blob = await match.blob();
            return URL.createObjectURL(blob);
        }
    } catch (e) {
        console.warn(`[AssetCache] Failed to load ${url} from cache, falling back to network:`, e);
    }
    return url;
};

initAssetCache().catch(console.error);
