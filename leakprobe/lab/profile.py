"""Lab profiles: YAML files in lab/profiles/ describing one VPN configuration plus ground truth."""

import ipaddress
from importlib import resources
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

TEST_IDS = (
    "LP-ROUTE-01", "LP-V6-01", "LP-DNS-01", "LP-KILL-01",
    "LP-START-01", "LP-SPLIT-01", "LP-EGRESS-01", "LP-IDENT-01",
)
Expected = Literal["pass", "fail", "warn"]


class WireGuardConfig(BaseModel):
    """Client-side WireGuard settings."""

    allowed_ips: list[str]
    dns: str | None = None  # None: client keeps the ISP resolver

    @field_validator("allowed_ips")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        for net in v:
            ipaddress.ip_network(net)
        return v


class ExtraRoute(BaseModel):
    """A route added on the client, e.g. a DHCP option 121 route (TunnelVision)."""

    dst: str
    via: str


class Profile(BaseModel):
    """One lab scenario."""

    name: str
    description: str
    wireguard: WireGuardConfig | None  # None: no tunnel is ever brought up
    firewall: Literal["none", "killswitch", "killswitch-v4"] = "none"
    extra_routes: list[ExtraRoute] = Field(default_factory=list)
    expected: dict[str, Expected] = Field(default_factory=dict)

    @field_validator("expected")
    @classmethod
    def _known_tests(cls, v: dict[str, Expected]) -> dict[str, Expected]:
        unknown = set(v) - set(TEST_IDS)
        if unknown:
            raise ValueError(f"unknown test ids: {sorted(unknown)}")
        return v


def _dir() -> resources.abc.Traversable:
    return resources.files("leakprobe.lab").joinpath("profiles")


def list_profiles() -> list[str]:
    """Names of the shipped profiles."""
    names = (p.name for p in _dir().iterdir())
    return sorted(n.removesuffix(".yaml") for n in names if n.endswith(".yaml"))


def load_profile(name: str) -> Profile:
    """Load and validate ``lab/profiles/<name>.yaml``."""
    path = _dir().joinpath(f"{name}.yaml")
    if not path.is_file():
        raise ValueError(f"unknown profile {name!r}; choose from: {', '.join(list_profiles())}")
    profile = Profile.model_validate(yaml.safe_load(path.read_text()))
    if profile.name != name:
        raise ValueError(f"profile file {name}.yaml declares name {profile.name!r}")
    return profile
