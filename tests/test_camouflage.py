import re

import pytest

from disguise import camouflage as cf
from test_barrier import SALT

SAFE_VALUE = re.compile(r"[a-z0-9_.:-]{1,64}")


@pytest.fixture
def cam():
    return cf.Camouflage(SALT, real_services={"http", "ssh"})


@pytest.mark.parametrize("raw", [
    "Server: nginx/1.18.0 (Ubuntu)",
    "Server: Apache/2.4.41 (Ubuntu)",
    "nginx/1.25.3",
])
def test_http_banner_loses_version_and_os(cam, raw):
    out = cf.normalize_banner("http", raw)
    assert out == "Server: web"
    for leak in ("1.18", "2.4", "Ubuntu", "1.25", "nginx", "Apache"):
        assert leak not in out


def test_ssh_banner_normalized():
    assert cf.normalize_banner("ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4") == "SSH-2.0-OpenSSH"


def test_unknown_service_rejected():
    with pytest.raises(cf.CamouflageError):
        cf.normalize_banner("quake", "banner")


def test_real_host_shows_only_its_services(cam):
    p = cam.profile("web-01")
    assert p["bait"] is False and p["open_services"] == ["http", "ssh"]
    assert p["banners"]["http"] == "Server: web" and p["os"] == "generic"


def test_real_host_hides_unrun_service(cam):
    assert cam.answer("web-01", "ftp") is None     # not running -> looks closed
    assert cam.answer("web-01", "http") == "Server: web"


def test_bait_profile_is_consistent_per_host(cam):
    a = cam.profile("decoy-01", bait=True)
    b = cam.profile("decoy-01", bait=True)
    assert a == b  # same host always presents the same personality


def test_different_bait_hosts_can_differ(cam):
    profiles = {tuple(cam.profile(f"decoy-{i:02d}", bait=True)["open_services"]) for i in range(20)}
    assert len(profiles) > 1  # not all identical


def test_bait_answers_match_its_profile(cam):
    prof = cam.profile("decoy-07", bait=True)
    for svc in ("http", "ssh", "smtp", "ftp"):
        ans = cam.answer("decoy-07", svc, bait=True)
        if svc in prof["open_services"]:
            assert ans == prof["banners"].get(svc, "")
        else:
            assert ans is None


def test_no_banner_leaks_version_digits(cam):
    for host, bait in [("web-01", False)] + [(f"d-{i}", True) for i in range(10)]:
        for b in cam.profile(host, bait)["banners"].values():
            assert not re.search(r"\d+\.\d+", b.replace("SSH-2.0-", ""))  # SSH-2.0 is the required protocol id, not a version leak


def test_bad_host_name_rejected(cam):
    with pytest.raises(cf.CamouflageError):
        cam.profile("../etc", bait=True)


def test_unknown_real_service_rejected():
    with pytest.raises(cf.CamouflageError):
        cf.Camouflage(SALT, real_services={"http", "quake"})


def test_summary(cam):
    print("\nCAMOUFLAGE:")
    print(f"  real web-01 presents: {cam.profile('web-01')['banners']}")
    print(f"  real banner 'Server: nginx/1.18.0 (Ubuntu)' -> '{cf.normalize_banner('http', 'Server: nginx/1.18.0 (Ubuntu)')}'")
    for i in (1, 2, 3):
        p = cam.profile(f"decoy-{i:02d}", bait=True)
        print(f"  decoy-{i:02d} looks like: {p['os']:<8} open={p['open_services']}")
    assert True
