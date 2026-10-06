/* VULNLAB CTF portal logic (vanilla JS - no framework) */
(function () {
  "use strict";
  var API = ""; // same origin (9090)
  var token = localStorage.getItem("vl_student_token") || "";
  var handle = localStorage.getItem("vl_handle") || "";
  var prevRank = parseInt(localStorage.getItem("vl_rank") || "0", 10);
  var challenges = [];
  var me = null;

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? "" : s).replace(/[<>&]/g, function (c) {
    return { "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]; }); }

  function toast(msg, kind) {
    var t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.innerHTML = msg;
    $("toasts").appendChild(t);
    setTimeout(function () { t.remove(); }, 5200);
  }

  function jget(path) {
    return fetch(API + path).then(function (r) { return r.json(); });
  }
  function jpost(path, body) {
    return fetch(API + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }).then(function (r) { return r.json().then(function (j) { j._http = r.status; return j; }); });
  }

  /* ---------------- registration ---------------- */
  function openGate() { $("gate").classList.remove("hide"); }
  function closeGate() { $("gate").classList.add("hide"); }

  function enterLab() {
    var h = $("handle").value.trim();
    if (!h) { $("gateMsg").textContent = "handle required"; return; }
    jpost("/api/register", { handle: h }).then(function (r) {
      if (!r.student_token) { $("gateMsg").textContent = r.error || "registration failed"; return; }
      token = r.student_token; handle = r.handle;
      localStorage.setItem("vl_student_token", token);
      localStorage.setItem("vl_handle", handle);
      closeGate();
      boot();
    });
  }

  /* ---------------- data load ---------------- */
  function loadChallenges() {
    return fetch(API + "/api/challenges?student_token=" + encodeURIComponent(token))
      .then(function (r) { return r.json(); })
      .then(function (j) { challenges = j.challenges || []; renderCards(); fillSelects(); });
  }

  function loadMe() {
    if (!token) return Promise.resolve();
    return fetch(API + "/api/me?student_token=" + encodeURIComponent(token))
      .then(function (r) { if (r.status === 401) { openGate(); return null; } return r.json(); })
      .then(function (j) {
        if (!j || j.error) return;
        var oldRank = me ? me.rank : prevRank;
        me = j;
        localStorage.setItem("vl_rank", String(j.rank || 0));
        $("dHandle").textContent = j.handle;
        $("stScore").textContent = j.score;
        $("stRank").textContent = j.rank ? "#" + j.rank : "—";
        var pct = j.total_flags ? Math.round(100 * j.flags / j.total_flags) : 0;
        $("ringPrg").style.strokeDashoffset = String(377 - 377 * pct / 100);
        $("ringNum").textContent = pct + "%";
        $("ringFlags").textContent = j.flags + " / " + j.total_flags;
        $("dFlags").textContent = j.flags + " / " + j.total_flags;
        renderMySolves(j);
        renderBadges(j);
        renderGraph(j);
        if (prevRank && j.rank && j.rank > prevRank) {
          toast("<b>RANK CHANGE</b><br>a player overtook you. #" + prevRank + " → #" + j.rank, "warn");
        }
        prevRank = j.rank;
        if (j.solved.indexOf("boot-02") >= 0) showRooted();
        renderCats(j);
        if (oldRank && j.rank && j.rank < oldRank) {
          /* rank improved - subtle info toast */
        }
      });
  }

  function loadStatus() {
    jget("/api/status").then(function (j) {
      $("tgtHost").textContent = j.target;
      $("dHost").textContent = j.target;
      $("dMode").textContent = j.mode;
      $("footMode").textContent = "mode: " + j.mode;
      $("stPlayers").textContent = j.players;
      $("stFlags").textContent = j.flags_solved + " / " + j.flags_total;
      $("dFlags").textContent = (me ? me.flags : 0) + " / " + j.flags_total;
      var up = Object.keys(j.services).filter(function (k) { return j.services[k]; }).length;
      var online = j.services.web || j.services.waf || j.services.ftp;
      $("tgtDot").className = "dot" + (online ? " on" : "");
      $("tgtState").textContent = online ? "ONLINE" : "OFFLINE";
      var chips = "";
      var names = { web: "5000 web/api", waf: "5050 waf", ftp: "2121 ftp", telnet: "2323 telnet",
        ssh: "2222 ssh", debug: "8000 debug-lab", rabbit1: "6379 ?", rabbit2: "8081 ?" };
      Object.keys(names).forEach(function (k) {
        chips += '<span class="chip ' + (j.services[k] ? "up" : "down") + '">' +
          names[k] + (j.services[k] ? "" : " down") + "</span>";
      });
      $("svcChips").innerHTML = chips;
      var tb = "";
      var ports = { web: [":5000", "HTTP / API"], waf: [":5050", "WAF GATE"],
        ftp: [":2121", "FTP"], telnet: [":2323", "TELNET"], ssh: [":2222", "SSH"],
        debug: [":8000", "DEBUG-LAB (hidden)"] };
      Object.keys(ports).forEach(function (k) {
        tb += "<tr><td>" + ports[k][0] + "</td><td>" + ports[k][1] + "</td><td>" +
          (j.services[k] ? '<span style="color:var(--green)">online</span>'
            : '<span style="color:var(--red)">down</span>') + "</td></tr>";
      });
      $("svcTable").querySelector("tbody").innerHTML = tb;
    });
  }

  function loadLeaderboard() {
    jget("/api/leaderboard").then(function (j) {
      var rows = j.leaderboard || [], tb = "", snap = "";
      rows.slice(0, 50).forEach(function (r) {
        var mine = (r.handle === handle) ? ' class="me"' : "";
        tb += "<tr" + mine + "><td>#" + r.rank + "</td><td>" + esc(r.handle) +
          (r.flags >= 1 && r.flags < 5 ? ' <span class="muted">(low)</span>' : "") +
          "</td><td class='num'>" + r.score + "</td><td class='num'>" + r.flags +
          "</td><td>" + (r.last_solve || "—") + "</td></tr>";
      });
      $("lbTable").querySelector("tbody").innerHTML = tb || '<tr><td colspan=5 class=muted>no players yet</td></tr>';
      rows.slice(0, 5).forEach(function (r) {
        snap += "<tr><td>#" + r.rank + "</td><td>" + esc(r.handle) + "</td><td class='num'>" + r.score + "</td></tr>";
      });
      $("snapTable").querySelector("tbody").innerHTML = snap;
    });
  }

  /* ---------------- live solve feed ---------------- */
  var lastRank = 0, feedSeen = {};

  function loadFeed() {
    jget("/api/feed").then(function (j) {
      var rows = j.feed || [], tb = "";
      rows.slice(0, 12).forEach(function (r) {
        var mine = (r.handle === handle);
        var key = r.handle + "|" + r.challenge_id + "|" + r.at;
        var fresh = !feedSeen[key] && Object.keys(feedSeen).length > 0;
        feedSeen[key] = 1;
        tb += '<tr class="' + (mine ? "me" : "") + (fresh ? " fresh" : "") + '">' +
          "<td>" + esc(r.at) + "</td><td>" + esc(r.handle) + "</td>" +
          '<td title="' + esc(r.challenge_id) + '">' + esc(r.challenge) + "</td>" +
          '<td class="num">+' + r.points + "</td></tr>";
      });
      $("feedTable").querySelector("tbody").innerHTML =
        tb || '<tr><td colspan=4 class=muted>no solves yet - be the first</td></tr>';
      $("feedStamp").textContent = "updated " + (j.server_time || "");

      // my standing, straight from the same board the feed uses
      var meRow = null;
      jget("/api/leaderboard").then(function (b) {
        (b.leaderboard || []).forEach(function (r) {
          if (r.handle === handle) { meRow = r; }
        });
        if (!meRow) {
          $("myRank").textContent = "—";
          $("myScore").textContent = "0";
          $("myFlags").textContent = "0";
          return;
        }
        $("myRank").textContent = "#" + meRow.rank;
        $("myScore").textContent = meRow.score;
        $("myFlags").textContent = meRow.flags;
        if (lastRank && meRow.rank < lastRank) {
          $("myMove").innerHTML = '<span style="color:var(--green)">up ' +
            (lastRank - meRow.rank) + "</span>";
        } else if (lastRank && meRow.rank > lastRank) {
          $("myMove").innerHTML = '<span style="color:var(--red)">down ' +
            (meRow.rank - lastRank) + "</span>";
        } else if (lastRank) {
          $("myMove").textContent = "holding";
        }
        lastRank = meRow.rank;
      });
    });
  }

  /* ---------------- challenges ---------------- */
  function renderCards() {
    var cat = $("fCat").value, diff = $("fDiff").value, state = $("fState").value;
    var q = ($("fSearch").value || "").toLowerCase();
    var html = "", n = 0;
    challenges.forEach(function (c) {
      if (cat && c.category !== cat) return;
      if (diff && c.difficulty !== diff) return;
      if (state === "solved" && !c.solved) return;
      if (state === "open" && (c.solved || c.locked)) return;
      if (state === "locked" && !c.locked) return;
      if (q && (c.name + " " + c.id + " " + c.description).toLowerCase().indexOf(q) < 0) return;
      n++;
      var cls = "card" + (c.solved ? " solved" : "") + (c.locked ? " locked" : "");
      var hints = "";
      (c.hints_released || []).forEach(function (lv) {
        hints += '<div class="hintbox">H' + lv + " unlocked (-" + (lv * 10) + "%)</div>";
      });
      html += '<div class="' + cls + '">' +
        '<span class="tag ' + c.difficulty.toLowerCase() + '">' + c.difficulty + "</span>" +
        '<div class="cat">' + esc(c.category) + " · " + esc(c.id) + "</div>" +
        "<h4>" + esc(c.name) + (c.solved ? ' <span style="color:var(--green)">✓</span>' : "") + "</h4>" +
        '<div class="desc">' + esc(c.description) + "</div>" +
        hints +
        (c.locked ? '<div class="hintbox" style="border-color:var(--red);color:var(--red)">' + esc(c.lock_reason) + "</div>" : "") +
        '<div class="foot"><span class="pts">' + c.effective_points + " pts</span>" +
        '<span class="cwe">' + esc(c.cwe || "") + "</span></div>" +
        '<div class="actions">' +
        '<input id="in-' + c.id + '" placeholder="flag" ' + (c.solved || c.locked ? "disabled" : "") + ">" +
        '<button class="btn" data-submit="' + c.id + '" ' + (c.solved || c.locked ? "disabled" : "") + ">SEND</button>" +
        "</div></div>";
    });
    $("cards").innerHTML = html || '<p class="muted">no challenges match the filter</p>';
    $("chCount").textContent = n + " shown / " + challenges.length + " total";
  }

  function fillSelects() {
    var cats = {};
    challenges.forEach(function (c) { cats[c.category] = 1; });
    var opts = '<option value="">all categories</option>';
    Object.keys(cats).forEach(function (k) { opts += "<option>" + esc(k) + "</option>"; });
    $("fCat").innerHTML = opts;
    var o2 = "";
    challenges.forEach(function (c) {
      o2 += '<option value="' + c.id + '">' + esc(c.id) + " — " + esc(c.name) + "</option>";
    });
    $("qsChallenge").innerHTML = o2;
    $("hintChallenge").innerHTML = o2;
  }

  function submitFlag(cid, value, afterInput) {
    if (!value) return;
    jpost("/api/submit", { student_token: token, challenge_id: cid, flag: value }).then(function (r) {
      if (r.result === "correct") {
        showCapture(r);
        toast("ACCESS GRANTED — <b>" + esc(r.challenge) + "</b> +" + r.points + " pts");
        if (afterInput) afterInput.value = "";
      } else if (r.result === "decoy") {
        toast(r.message, "warn");
        if (afterInput) afterInput.value = "";
      } else if (r.result === "cooldown") {
        toast("HTTP 429 — " + r.message, "warn");
      } else {
        toast((r._http ? "HTTP " + r._http + " — " : "") + (r.message || "rejected"), r.result === "locked" ? "warn" : "info");
      }
      loadChallenges(); loadMe(); loadLeaderboard();
    });
  }

  function showCapture(r) {
    $("capHd").textContent = r.first_blood ? "FIRST BLOOD" : "ACCESS GRANTED";
    $("capSub").textContent = "FLAG CAPTURED";
    $("capPts").textContent = "+" + r.points + " POINTS" +
      (r.first_blood ? " (incl. first blood +" + r.first_blood_bonus + ")" : "");
    $("capFlag").textContent = r.challenge;
    $("capRank").textContent = "RANK: #" + (r.rank || "?");
    $("capCat").textContent = "CATEGORY: " + (r.category || "").toUpperCase() +
      (r.cwe ? "  ·  " + r.cwe : "");
    $("captureBox").classList.remove("rooted");
    $("overlay").classList.add("show");
    if (r.achievements && r.achievements.length) {
      setTimeout(function () {
        toast("ACHIEVEMENT UNLOCKED — <b>" + esc(r.achievements.join(", ")) + "</b>", "info");
      }, 600);
    }
  }

  function showRooted() {
    if (sessionStorage.getItem("vl_rooted_shown")) return;
    sessionStorage.setItem("vl_rooted_shown", "1");
    $("captureBox").classList.add("rooted");
    $("capHd").textContent = "████████████████████████";
    $("capSub").innerHTML = "<b style='color:#ff4d5e;font-size:22px'>SYSTEM ROOTED</b><br>" +
      "████████████████████████<br><br>USER: root<br>FLAG: VULNLAB{rooted_the_box}";
    $("capPts").textContent = "BOX PWNED";
    $("capRank").textContent = "";
    $("capCat").textContent = "+500 POINTS · ROOT ACCESS ACHIEVEMENT";
    $("overlay").classList.add("show");
  }

  function renderMySolves(j) {
    if (!j.solves.length) {
      $("mySolves").innerHTML = "No flags captured yet. Start with recon.";
      return;
    }
    var html = "<table><thead><tr><th>Challenge</th><th>When (UTC)</th><th style='text-align:right'>Pts</th></tr></thead><tbody>";
    j.solves.slice().reverse().forEach(function (s) {
      html += "<tr><td>" + esc(s.challenge_id) + (s.first_blood ? ' <span style="color:#ffd85e">★FB</span>' : "") +
        "</td><td class=muted>" + esc(s.solved_at) + "</td><td class='num'>" + s.points + "</td></tr>";
    });
    html += "</tbody></table>";
    $("mySolves").innerHTML = html;
  }

  function renderBadges(j) {
    var have = {};
    (j.achievements || []).forEach(function (k) { have[k] = 1; });
    var html = "";
    (j.all_achievements || []).forEach(function (a) {
      html += '<span class="badge ' + (have[a.key] ? "on" : "") +
        (a.key === "root_access" ? " root" : "") + '">' +
        (have[a.key] ? "● " : "○ ") + esc(a.name) + "</span>";
    });
    $("badges").innerHTML = html + '<p class="muted">Rabbit Hole Survivor unlocks when you submit a known decoy.</p>';
  }

  function renderGraph(j) {
    var g = j.graph || {};
    document.querySelectorAll(".gnode").forEach(function (n) {
      var st = g[n.getAttribute("data-node")];
      n.className = "gnode " + (st === "done" ? "done" : st === "locked" ? "locked" : "");
    });
  }

  function renderCats(j) {
    var byCat = {};
    challenges.forEach(function (c) {
      byCat[c.category] = byCat[c.category] || { t: 0, s: 0 };
      byCat[c.category].t++;
      if (j.solved.indexOf(c.id) >= 0) byCat[c.category].s++;
    });
    var html = "";
    Object.keys(byCat).sort().forEach(function (k) {
      var v = byCat[k], pct = Math.round(100 * v.s / v.t);
      html += '<div class="kv"><span>' + esc(k) + "</span><b>" + v.s + "/" + v.t + "</b></div>" +
        '<div style="height:5px;background:#16202a;border-radius:3px;margin-bottom:6px">' +
        '<div style="height:5px;width:' + pct + '%;background:var(--green);border-radius:3px"></div></div>';
    });
    $("catBars").innerHTML = html;
  }

  /* ---------------- events ---------------- */
  document.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    if (b.id === "enterBtn") return enterLab();
    if (b.id === "capClose") return $("overlay").classList.remove("show");
    if (b.id === "qsBtn") {
      return submitFlag($("qsChallenge").value, $("qsFlag").value.trim(), $("qsFlag"));
    }
    if (b.id === "hintBtn") {
      var cid = $("hintChallenge").value, lv = parseInt($("hintLevel").value, 10);
      jpost("/api/hint", { student_token: token, challenge_id: cid, level: lv }).then(function (r) {
        if (r.hint) {
          $("hintOut").innerHTML = '<div class="hintbox"><b>' + esc(cid) + " · Hint " + lv +
            "</b> (-" + r.cost + " pts → now " + r.effective_points + " pts)<br>" + esc(r.hint) + "</div>";
          loadChallenges();
        } else {
          $("hintOut").innerHTML = '<div class="hintbox" style="color:var(--red)">' + esc(r.error || "failed") + "</div>";
        }
      });
      return;
    }
    if (b.hasAttribute("data-submit")) {
      var id = b.getAttribute("data-submit");
      var input = $("in-" + id);
      submitFlag(id, input.value.trim(), input);
      return;
    }
    if (b.parentElement && b.parentElement.id === "nav") {
      document.querySelectorAll("#nav button").forEach(function (x) { x.classList.remove("active"); });
      b.classList.add("active");
      document.querySelectorAll(".section").forEach(function (s) { s.classList.remove("active"); });
      $("s-" + b.getAttribute("data-s")).classList.add("active");
    }
  });

  ["fCat", "fDiff", "fState", "fSearch"].forEach(function (id) {
    document.addEventListener("input", function (e) {
      if (e.target.id === id) renderCards();
    });
    document.addEventListener("change", function (e) {
      if (e.target.id === id) renderCards();
    });
  });
  $("handle").addEventListener("keydown", function (e) { if (e.key === "Enter") enterLab(); });

  /* ---------------- boot ---------------- */
  function boot() {
    loadStatus(); loadChallenges(); loadMe(); loadLeaderboard(); loadFeed();
    setInterval(loadStatus, 8000);
    setInterval(loadLeaderboard, 8000);
    setInterval(loadMe, 10000);
    setInterval(loadChallenges, 20000);
    setInterval(loadFeed, 5000);
  }

  if (token) { closeGate(); boot(); } else { openGate(); loadStatus(); loadLeaderboard(); }
})();
