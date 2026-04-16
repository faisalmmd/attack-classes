// TC-CM-01: POSITIVE — Coinhive initialization
var miner = new CoinHive.Anonymous('xhIjAfwL60rB8FLxGo0P4dMNmKdN3YBO');
miner.start();

// TC-CM-02: POSITIVE — generic miner pattern
var m = new Client('abc123sitekeylongformat');
m.start();
m.setThrottle(0.5);

// TC-CM-03: POSITIVE — known miner domain in script src
// <script src="https://coinhive.com/lib/coinhive.min.js"></script>
var loader = "coinhive.com/lib/coinhive.min.js";

// TC-CM-04: POSITIVE — mining pool WebSocket
var ws = new WebSocket("wss://pool.coinhive.com/proxy");

// TC-CM-05: POSITIVE — algorithm reference
function cn_slow_hash(input) { /* cryptonight implementation */ }

// TC-CM-06: NEGATIVE — comment about mining, not actual mining
// This site does NOT use cryptocurrency mining

// TC-CM-07: NEGATIVE — price lookup, not mining
var bitcoin_price = fetchPrice("BTC");
var ethereum_value = getMarketCap("ETH");
