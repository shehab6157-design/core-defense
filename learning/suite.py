"""Regression suite: labeled scenarios every learned version must still pass (Phase 6).

Each entry: (name, label, expected (action, reason) for attacks or None, [(time, fact), ...]).
If learning would make ANY attack scenario go undetected, the new version is refused.
"""
H = "web-01"
INVENTORY = frozenset({H})


def _fail(ip="6.6.6.6"):
    return {"kind": "login_failed", "host": H, "user": "root", "src_ip": ip,
            "port": 22, "method": "password", "invalid_user": False}


def _ok(ip="6.6.6.6"):
    return {"kind": "login_success", "host": H, "user": "root", "src_ip": ip,
            "port": 22, "method": "password"}


SUITE = [
    ("brute-force-6", "attack", ("watch", "brute-force"),
     [(float(i), _fail()) for i in range(6)]),
    ("login-after-6-fails", "attack", ("limit_access", "login-after-brute-force"),
     [(float(i), _fail()) for i in range(6)] + [(7.0, _ok())]),
    ("web-shell", "attack", ("limit_access", "service-spawned-shell"),
     [(0.0, {"kind": "process_spawn", "host": H, "parent": "nginx", "child": "sh", "user": "www-data"})]),
    ("ransomware-burst", "attack", ("limit_access", "mass-file-change"),
     [(0.0, {"kind": "file_burst", "host": H, "modified": 400, "renamed": 0, "window": 60})]),
    ("lateral-85", "attack", ("deploy_decoy", "lateral-movement"),
     [(0.0, {"kind": "lateral_movement", "host": H, "src_ip": "10.0.2.10",
             "dst_ip": "10.0.2.11", "confidence": 85, "techniques": []})]),
    ("typo-then-login", "benign", None,
     [(0.0, _fail("192.168.109.1")), (5.0, _fail("192.168.109.1")), (10.0, _ok("192.168.109.1"))]),
    ("small-file-work", "benign", None,
     [(0.0, {"kind": "file_burst", "host": H, "modified": 20, "renamed": 1, "window": 60})]),
]
