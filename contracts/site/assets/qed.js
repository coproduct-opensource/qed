// QED's only script. Three progressive enhancements; every page reads in
// full without it. (1) Copy buttons for preformatted text. (2) On /verify,
// the acceptance rule run in this tab, downloaded only when asked for.
// (3) On the ledger page, the live list of board posts, read in the browser
// from a public RPC endpoint. Nothing here talks to a server of the site's
// authors; the checker and its inputs are static files of this site.
"use strict";
(function () {
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    var target = document.getElementById(button.getAttribute("data-copy"));
    if (!target || !navigator.clipboard) return;
    button.hidden = false;
    var label = button.textContent;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(target.textContent).then(
        function () { button.textContent = "Copied"; setTimeout(function () { button.textContent = label; }, 1500); },
        function () { button.textContent = "Copy failed: select the text instead"; }
      );
    });
  });

  (function checker() {
    var box = document.getElementById("checker");
    if (!box || !window.WebAssembly || !window.crypto || !crypto.subtle) return;
    box.hidden = false;
    var select = document.getElementById("checker-order");
    var run = document.getElementById("checker-run");
    var status = document.getElementById("checker-status");
    var out = document.getElementById("checker-verdict");
    var want = new URLSearchParams(location.search).get("order");
    if (want) {
      Array.prototype.forEach.call(select.options, function (o) {
        if (o.getAttribute("data-id") === want) select.value = o.value;
      });
      document.getElementById("checker-box").open = true;
    }
    function hex(buffer) {
      return Array.prototype.map.call(new Uint8Array(buffer), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    }
    async function fetchBytes(url) {
      if (!/^\/[^\/\\]/.test(url)) throw new Error(url + ": not a path on this site");
      var response = await fetch(url, { credentials: "omit" });
      if (!response.ok) throw new Error(url + ": HTTP " + response.status);
      return new Uint8Array(await response.arrayBuffer());
    }
    function row(term, text, cls) {
      var dt = document.createElement("dt"); dt.textContent = term;
      var dd = document.createElement("dd"); dd.textContent = text;
      if (cls) dd.className = cls;
      out.appendChild(dt); out.appendChild(dd);
    }
    var compiled = null;
    run.addEventListener("click", async function () {
      run.disabled = true;
      out.hidden = true;
      out.textContent = "";
      status.className = "";
      try {
        if (!compiled) {
          status.textContent = "Downloading the checker (" + box.getAttribute("data-bytes") + " bytes)…";
          var wasm = await fetchBytes(box.getAttribute("data-wasm"));
          var got = hex(await crypto.subtle.digest("SHA-256", wasm));
          if (got !== box.getAttribute("data-sha256")) throw new Error("the checker's SHA-256 is " + got + ", not the one this page names");
          compiled = await WebAssembly.compile(wasm);
        }
        status.textContent = "Fetching the receipt, statement and artifact…";
        var receipt = JSON.parse(new TextDecoder().decode(await fetchBytes(select.value)));
        var acceptance = receipt.acceptance;
        if (!acceptance) throw new Error("this receipt has no statement to check against");
        var statement = await fetchBytes(acceptance.statement.url);
        var artifact = await fetchBytes(receipt.artifact.url);
        status.textContent = "Checking in this tab…";
        await new Promise(function (resolve) { setTimeout(resolve, 30); });
        var started = performance.now();
        var verdict;
        try {
          var e = (await WebAssembly.instantiate(compiled, {})).exports;
          var put = function (bytes) {
            var p = e.qed_alloc(bytes.length);
            new Uint8Array(e.memory.buffer, p, bytes.length).set(bytes);
            return [p, bytes.length];
          };
          var pl = put(new TextEncoder().encode(JSON.stringify(acceptance.policy)));
          var st = put(statement);
          var ar = put(artifact);
          var packed = e.qed_check(pl[0], pl[1], st[0], st[1], ar[0], ar[1]);
          var ptr = Number(packed >> 32n), len = Number(packed & 0xffffffffn);
          verdict = JSON.parse(new TextDecoder().decode(new Uint8Array(e.memory.buffer, ptr, len)));
        } catch (trap) {
          if (trap instanceof WebAssembly.RuntimeError && /unreachable/i.test(trap.message)) {
            verdict = { verdict: "refused", refusal: "KernelRefused", detail: "the checker aborted, as the proof program does on a kernel refusal" };
          } else {
            throw new Error("the browser could not finish the check (" + trap.message + "). This is not a verdict");
          }
        }
        var seconds = ((performance.now() - started) / 1000).toFixed(1);
        row("Verdict", verdict.verdict === "accepted" ? "Accepted: " + verdict.proof + " proves the claim (" + verdict.declarations + " declarations checked)" : "Refused: " + verdict.refusal + (verdict.detail ? " — " + verdict.detail : ""), verdict.verdict === "accepted" ? "ok" : "bad");
        if (verdict.policyHash) row("Policy hash", verdict.policyHash === receipt.order.policyHash ? "equals the order's on-chain policyHash" : "DIFFERS from the order's policyHash " + receipt.order.policyHash, verdict.policyHash === receipt.order.policyHash ? "ok" : "bad");
        if (verdict.artifactKeccak256) row("Artifact Keccak-256", verdict.artifactKeccak256 === receipt.artifact.recordedByVault ? "equals the vault's artifactOf record" : "DIFFERS from the vault's record " + receipt.artifact.recordedByVault, verdict.artifactKeccak256 === receipt.artifact.recordedByVault ? "ok" : "bad");
        row("Time", seconds + " s in this tab");
        out.hidden = false;
        status.textContent = "";
      } catch (error) {
        status.className = "bad";
        status.textContent = "No verdict: " + error.message + ".";
      } finally {
        run.disabled = false;
      }
    });
  })();

  var dataNode = document.getElementById("site-data");
  if (!dataNode || !document.getElementById("live")) return;
  var site = JSON.parse(dataNode.textContent);
  var POSTED = site.topics.posted, WITHDRAWN = site.topics.withdrawn;
  // Blocks per eth_getLogs: what the page's default endpoint allows, or
  // 5,000,000 (the Arbitrum Sepolia endpoint allows 10,000,000).
  var CHUNK = site.network.logRange || 5000000;

  function word(data, index) { return data.substr(2 + 64 * index, 64); }
  function addressOf(w) { return "0x" + w.substr(24); }
  function decimal(w) { return BigInt("0x" + w).toString(10); }
  function utf8(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(2 * i, 2), 16);
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  // Posted(bytes32 indexed id, address indexed poster, address vault, Task task).
  // Data: vault, offset of the task tuple; the tuple is twelve static words,
  // then the offset of the string within the tuple, then length and bytes.
  function decodeLog(log) {
    var topics = log.topics, data = log.data;
    if (topics[0] === WITHDRAWN) {
      if (topics.length !== 2) throw new Error("malformed Withdrawn log");
      return { kind: "withdrawn", id: topics[1] };
    }
    if (topics[0] !== POSTED) throw new Error("not a board event");
    if (topics.length !== 3) throw new Error("malformed Posted log");
    var words = (data.length - 2) / 64;
    if (data.length < 2 + 64 * 2 || (data.length - 2) % 64 !== 0) throw new Error("malformed Posted data");
    var base = Number(BigInt("0x" + word(data, 1))) / 32;
    if (!Number.isInteger(base) || base + 13 > words) throw new Error("task offset out of range");
    var t = function (i) { return word(data, base + i); };
    var text = Number(BigInt("0x" + t(12))) / 32;
    if (!Number.isInteger(text) || base + text + 1 > words) throw new Error("string offset out of range");
    var length = Number(BigInt("0x" + word(data, base + text)));
    var start = 2 + 64 * (base + text + 1);
    if (length > 128 || start + 2 * length > data.length) throw new Error("string length out of range");
    return {
      kind: "posted",
      id: topics[1],
      poster: addressOf(topics[2].substr(2)),
      vault: addressOf(word(data, 0)),
      statementSha256: "0x" + t(0),
      statementBlake3: "0x" + t(1),
      policyHash: "0x" + t(2),
      asset: addressOf(t(3)),
      maximumAmount: decimal(t(4)),
      verifier: addressOf(t(5)),
      program: "0x" + t(6),
      fundBy: decimal(t(7)),
      deliverBy: decimal(t(8)),
      buyerNode: "0x" + t(9),
      buyerKeyBinding: "0x" + t(10),
      salt: "0x" + t(11),
      buyerAddress: utf8(data.substr(start, 2 * length))
    };
  }

  // Compare the decoder with logs the Rust reference encoded.
  function selfTest() {
    var failures = [];
    site.vectors.forEach(function (vector, index) {
      try {
        var got = decodeLog({ topics: vector.topics, data: vector.data });
        Object.keys(vector.expect).forEach(function (key) {
          if (got[key] !== vector.expect[key]) failures.push("vector " + index + ": " + key + " is " + got[key] + ", expected " + vector.expect[key]);
        });
        Object.keys(got).forEach(function (key) {
          if (!(key in vector.expect)) failures.push("vector " + index + ": unexpected " + key);
        });
      } catch (error) { failures.push("vector " + index + ": " + error.message); }
    });
    return failures;
  }

  function el(tag, text, attrs) {
    var node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = text;
    if (attrs) Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }
  function short(hex) { return hex.length > 22 ? hex.substr(0, 12) + "…" + hex.substr(-8) : hex; }
  function mono(hex) { var c = el("code", short(hex)); c.title = hex; return c; }
  function units(amount) {
    var d = site.token.decimals, s = amount.padStart(d + 1, "0");
    var whole = s.slice(0, -d), frac = s.slice(-d).replace(/0+$/, "");
    return (frac ? whole + "." + frac : whole) + " " + site.token.name;
  }
  function when(seconds) {
    var n = Number(seconds);
    return Number.isSafeInteger(n) ? new Date(n * 1000).toISOString().replace(".000Z", "Z") : seconds;
  }

  async function rpc(url, method, params) {
    var response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: method, params: params })
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    var body = await response.json();
    if (body.error) throw new Error(body.error.message || "RPC error");
    return body.result;
  }

  async function load() {
    var status = document.getElementById("tasks-status");
    var table = document.getElementById("tasks-table");
    var rows = document.getElementById("tasks-rows");
    var url = document.getElementById("rpc-url").value.trim();
    rows.textContent = "";
    table.hidden = true;
    status.className = "";
    status.textContent = "Reading the board from " + url + " …";
    try {
      var chain = Number(BigInt(await rpc(url, "eth_chainId", [])));
      if (chain !== site.network.chainId) throw new Error("that endpoint serves chain " + chain + ", not " + site.network.chainId);
      var head = Number(BigInt(await rpc(url, "eth_blockNumber", [])));
      var now = Number(BigInt((await rpc(url, "eth_getBlockByNumber", ["latest", false])).timestamp));
      var posts = [], withdrawn = {}, queries = 0;
      for (var from = site.board.deployBlock; from <= head; from += CHUNK) {
        var to = Math.min(head, from + CHUNK - 1);
        if (++queries > 40) throw new Error("the board's history is longer than this page will scan (40 queries)");
        var logs = await rpc(url, "eth_getLogs", [{
          address: site.board.address, fromBlock: "0x" + from.toString(16), toBlock: "0x" + to.toString(16)
        }]);
        logs.forEach(function (log) {
          // Only the board's own logs count, whatever the endpoint returns.
          if (String(log.address).toLowerCase() !== site.board.address) return;
          try {
            var notice = decodeLog(log);
            if (notice.kind === "withdrawn") withdrawn[notice.id] = true;
            else { notice.transaction = log.transactionHash; posts.push(notice); }
          } catch (error) { /* not a post this page can read; left out */ }
        });
      }
      posts.reverse();
      posts.forEach(function (post) {
        var state = withdrawn[post.id] ? "withdrawn"
          : post.vault !== site.vault.address ? "names another vault"
          : Number(post.fundBy) < now ? "funding window closed" : "listed";
        var row = el("tr");
        var first = el("td");
        var link = el("a", null, { href: site.network.explorer + "/tx/" + post.transaction, rel: "noopener" });
        link.appendChild(mono(post.id));
        first.appendChild(link);
        row.appendChild(first);
        row.appendChild(el("td", state, { class: state === "listed" ? "ok" : "muted" }));
        row.appendChild(el("td", units(post.maximumAmount)));
        row.appendChild(el("td", when(post.fundBy)));
        row.appendChild(el("td", when(post.deliverBy)));
        var statement = el("td"); statement.appendChild(mono(post.statementSha256)); row.appendChild(statement);
        var program = el("td"); program.appendChild(mono(post.program));
        if (site.programs.indexOf(post.program.substr(2)) < 0) program.appendChild(el("span", " (not a program listed here)", { class: "muted" }));
        row.appendChild(program);
        var node = el("td"); node.appendChild(mono(post.buyerNode)); row.appendChild(node);
        var poster = el("td"); poster.appendChild(mono(post.poster));
        if (site.ours.indexOf(post.poster) >= 0) poster.appendChild(el("span", " (ours)", { class: "muted" }));
        row.appendChild(poster);
        rows.appendChild(row);
      });
      var open = posts.filter(function (p) { return !withdrawn[p.id] && p.vault === site.vault.address && Number(p.fundBy) >= now; }).length;
      status.textContent = posts.length + " post" + (posts.length === 1 ? "" : "s") + " on the board since block " + site.board.deployBlock + ", " + open + " listed (not withdrawn, funding window not yet closed), read at block " + head + ". A post is a notice: it does not show that the buyer has funds or will sign, and the board does not record whether a task has since been funded or settled.";
      table.hidden = posts.length === 0;
    } catch (error) {
      status.className = "bad";
      status.textContent = "Could not read the board from " + url + ": " + error.message + ". The rest of this page does not depend on it. Try another endpoint for chain " + site.network.chainId + ".";
    }
  }

  document.getElementById("live").hidden = false;
  document.getElementById("rpc-form").addEventListener("submit", function (event) { event.preventDefault(); load(); });
  if (new URLSearchParams(location.search).get("selftest") === "1") {
    var failures = selfTest();
    var box = document.getElementById("selftest");
    box.hidden = false;
    box.className = failures.length ? "bad" : "ok";
    box.textContent = failures.length
      ? "Decoder self-test FAILED: " + failures.join("; ")
      : "Decoder self-test passed: " + site.vectors.length + " logs encoded by the Rust reference decode to the same values here.";
  }
  load();
})();
