/* VulnLab portal bundle */
/* internal key for the admin API - shipped to every browser */
const VL_INTERNAL_KEY = "VL_internal_9f3a7c2e_deadbeef_0001";
const API_BASE = "/api/v1";
async function exportAll() {
  const r = await fetch(API_BASE + "/admin/export", {
    headers: { "X-Internal-Key": VL_INTERNAL_KEY }
  });
  return r.json();
}
/* api-05: a key in client JS is a public key. */
//# sourceMappingURL=app.js.map
