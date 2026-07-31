import http from "node:http";

const PORT = 3000;

// Merkle root matching proof-demo (18142334754527230829434618760706122867182291645357706712475860565891430848844)
const MERKLE_ROOT_HEX = "0x2823a0db02ca1edbe9b763ec25aeec3a5796df1db2e0388eb19ebefcdcc0343c";

const samplePolls = {
    polls: [
        {
            id: "1",
            merkle_root: MERKLE_ROOT_HEX,
            num_options: "3",
            deadline: "9999999999",
            total_votes: "0",
            active: true
        }
    ]
};

const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
    }

    console.log(`[Mock Relayer HTTP] ${req.method} ${req.url}`);

    if (req.url === "/api/polls" || req.url === "/polls") {
        res.writeHead(200);
        res.end(JSON.stringify(samplePolls));
        return;
    }

    if (req.url === "/api/vote" || req.url === "/vote") {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
            try {
                const payload = JSON.parse(body);
                console.log("[Mock Relayer] Received VoteRequest:", payload);
                res.writeHead(200);
                res.end(JSON.stringify({
                    tx_hash: "0x" + "a".repeat(64),
                    status: "broadcast"
                }));
            } catch (err) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: "Invalid JSON body" }));
            }
        });
        return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: "Not Found" }));
});

server.listen(PORT, "127.0.0.1", () => {
    console.log(`[Mock Relayer] Listening on http://127.0.0.1:${PORT}`);
});
