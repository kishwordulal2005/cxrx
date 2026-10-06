"""VulnLab API blueprint package (INTENTIONALLY VULNERABLE).

Blueprints:
  users.py  - enumeration, BOLA, excessive exposure, mass assignment, BFLA
  auth.py   - weak JWT secret, alg confusion, predictable reset, OTP, CORS
  admin.py  - shared-secret admin export, pickle cache, WAF-adjacent panels
  files.py  - upload filter bypasses, traversal, stored XSS, SSRF fetch
"""