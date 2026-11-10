"""Static tests of the container files. They need no Docker, so they run in every normal pytest / the gate, and catch the mistakes that are expensive to
find at build time: a missing test file in the image's test list, a root container, a secret in the build context, a compose file that opens privileges."""
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "Dockerfile").read_text()
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
IGNORE = [l.strip() for l in (ROOT / ".dockerignore").read_text().splitlines() if l.strip() and not l.startswith("#")]


def stages():
    return re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", DOCKERFILE, flags=re.M | re.I)


def stage_body(name):
    parts = re.split(r"^FROM\s+", DOCKERFILE, flags=re.M)
    for p in parts[1:]:
        if re.match(rf"\S+\s+AS\s+{re.escape(name)}\b", p, flags=re.I):
            return p
    raise AssertionError(f"stage {name} not found")


# ------------------------------------------------------------------------------------------------------------------------------------ Dockerfile

def test_it_is_a_multi_stage_build_with_the_stages_the_docs_name():
    names = stages()
    for needed in ("py-deps", "model", "backend-test", "ui-deps", "ui-test", "ui-build", "gate", "runtime", "demo", "final"):
        assert needed in names, (needed, names)
    assert len(set(names)) == len(names), "duplicate stage names"
    assert names[-1] == "final", "the default target (the last stage) must be the runtime image, not the demo or a test stage"
    assert re.search(r"^FROM\s+runtime\s+AS\s+final\s*$", DOCKERFILE, flags=re.M)


def test_the_final_image_is_gated_by_both_test_stages():
    rt = stage_body("runtime")
    assert "--mount=type=bind,from=gate" in rt and "/mnt/gate/backend" in rt and "/mnt/gate/ui" in rt
    gate = stage_body("gate")
    assert "--from=backend-test" in gate and "--from=ui-test" in gate
    assert "/gate/backend" in stage_body("backend-test") and "/gate/ui" in stage_body("ui-test")
    assert 'ARG TEST_LEVEL' in stage_body("backend-test") and 'ARG TEST_LEVEL' in stage_body("ui-test")        # an ARG must be re-declared per stage


def test_the_runtime_image_runs_as_a_non_root_user_with_a_healthcheck_and_one_entrypoint():
    rt = stage_body("runtime")
    assert re.search(r"^USER\s+sentinel\s*$", rt, flags=re.M)
    assert "useradd" in rt and "--uid 10001" in rt
    assert "HEALTHCHECK" in rt and "/health" in rt
    assert re.search(r'^ENTRYPOINT\s+\["sentinel-entrypoint"\]', rt, flags=re.M)
    assert "EXPOSE 8080" in rt
    assert "--workers" not in DOCKERFILE and "--workers" not in (ROOT / "docker/entrypoint.sh").read_text(), "the hub keeps state in memory: one process only"


def test_no_secret_or_environment_file_is_copied_into_any_layer_and_the_model_is_baked_in():
    assert not re.search(r"^(COPY|ADD)\b.*\.env\b(?!\.example)", DOCKERFILE, flags=re.M)
    assert not re.search(r"^ENV\b.*(TOKEN|SECRET|PASSWORD|KEY)=\S", DOCKERFILE, flags=re.M | re.I), "no credential may be baked in with ENV"
    rt = stage_body("runtime")
    assert "HF_HUB_OFFLINE=1" in rt and "COPY --from=model /opt/hf /opt/hf" in rt, "the container must never need huggingface.co at run time"
    assert "prefetch_model.py" in stage_body("model")


def test_the_runtime_stage_does_not_carry_the_test_suite_or_the_node_toolchain():
    rt = stage_body("runtime")
    assert "COPY tests" not in rt and "node_modules" not in rt and "--from=ui-deps" not in rt
    assert "COPY --from=ui-build /ui/dist /app/ui" in rt


def test_torch_comes_from_a_configurable_cpu_index_by_default():
    assert re.search(r"^ARG TORCH_INDEX_URL=https://download\.pytorch\.org/whl/cpu\s*$", DOCKERFILE, flags=re.M)


def test_embeddings_are_an_explicit_build_option_with_a_loud_fallback_when_off():
    assert re.search(r"^ARG EMBEDDINGS=1\s*$", DOCKERFILE, flags=re.M), "the default image must include PyTorch and the model"
    assert 'ARG EMBEDDINGS' in stage_body("py-deps") and 'ARG EMBEDDINGS' in stage_body("model")
    assert "sentence-transformers" in DOCKERFILE and 'EMBEDDINGS" = "1"' in stage_body("py-deps")
    assert "EMBEDDINGS" in (ROOT / "docker-compose.yml").read_text() and "SENTINEL_DOCKER_EMBEDDINGS" in (ROOT / "scripts/docker_test.sh").read_text()


def test_the_python_and_node_base_images_are_pinned_to_a_major_version_not_latest():
    for arg in re.findall(r"^ARG (?:PYTHON_IMAGE|NODE_IMAGE)=(\S+)", DOCKERFILE, flags=re.M):
        assert ":" in arg and not arg.endswith(":latest"), arg


# ------------------------------------------------------------------------------------------------------------------------------------ build context

@pytest.mark.parametrize("must_ignore", [".git", "**/.env", "**/.env.*", "**/node_modules", "**/__pycache__", "**/identity.json", "**/*.db", "**/*.pem", "frontend/dist"])
def test_dockerignore_keeps_secrets_and_junk_out_of_the_build_context(must_ignore):
    assert must_ignore in IGNORE


def test_the_example_env_file_is_trackable_and_holds_no_secret_values():
    assert "!**/.env.example" in IGNORE
    gi = (ROOT / ".gitignore").read_text().splitlines()
    assert "!.env.example" in gi and "!.dockerignore" in gi, ".gitignore's `.*` rule would otherwise hide the Docker support files from git"
    for line in (ROOT / ".env.example").read_text().splitlines():
        m = re.match(r"^(\w*(?:TOKEN|KEY|SECRET|PASSWORD)\w*)=(.*)$", line)
        if m:
            assert m.group(2).strip() == "", f"{m.group(1)} must be empty in the example file"


# ------------------------------------------------------------------------------------------------------------------------------------ compose

def test_compose_defines_the_hub_and_a_demo_profile_without_extra_privileges():
    svc = COMPOSE["services"]
    assert set(svc) == {"sentinel", "demo-agent"}
    assert svc["demo-agent"]["profiles"] == ["demo"], "the demo must not start with `up`"
    for name, s in svc.items():
        assert not s.get("privileged"), name
        assert s.get("cap_drop") == ["ALL"], name
        assert "no-new-privileges:true" in s.get("security_opt", []), name
        assert s.get("read_only") is True, name
        assert s.get("network_mode") != "host", name
        assert "pid" not in s and "ipc" not in s and "user" not in s or s.get("user") not in ("0", "root"), name


def test_compose_runs_one_hub_with_a_data_volume_and_loopback_only_publishing():
    s = COMPOSE["services"]["sentinel"]
    assert "deploy" not in s or s["deploy"].get("replicas", 1) == 1
    assert any(v.startswith("sentinel-data:/var/lib/sentinel") for v in s["volumes"])
    assert "sentinel-data" in COMPOSE["volumes"]
    assert any(p.startswith("${SENTINEL_BIND:-127.0.0.1}:") for p in s["ports"]), "published on loopback unless the operator opts out"
    assert s["environment"]["SENTINEL_EVENT_LOG"] == "/var/lib/sentinel/events.db"
    assert s["build"]["target"] == "final" and "TEST_LEVEL" in s["build"]["args"]
    assert COMPOSE["services"]["demo-agent"]["depends_on"]["sentinel"]["condition"] == "service_healthy"


def test_compose_has_no_hard_coded_credentials():
    text = (ROOT / "docker-compose.yml").read_text()
    for m in re.finditer(r"(TOKEN|SECRET|PASSWORD|LOG_KEY)\w*:\s*(\S+)", text):
        assert m.group(2).startswith("${"), f"credential-like setting must come from the environment: {m.group(0)}"


# ------------------------------------------------------------------------------------------------------------------------------------ scripts

def test_shell_scripts_have_valid_syntax_and_are_executable():
    for rel in ("docker/entrypoint.sh", "scripts/docker/backend_tests.sh"):
        p = ROOT / rel
        assert p.stat().st_mode & stat.S_IXUSR, rel
        assert subprocess.run(["sh", "-n", str(p)], capture_output=True).returncode == 0, rel


def test_every_test_file_the_image_build_runs_exists():
    """A renamed or deleted test file would otherwise only fail inside a 10-minute image build."""
    script = (ROOT / "scripts/docker/backend_tests.sh").read_text()
    paths = re.findall(r"\btests/[\w/.\-]+\.py\b|\btests/(?:contract|server)\b", script)
    assert len(paths) >= 12
    for p in paths:
        assert (ROOT / p).exists(), p


def test_the_demo_assets_the_dockerfile_copies_exist():
    for rel in ("tests/proxy/fake_downstream.py", "tests/proxy/agent_cli.py", "docker/demo/proxy.json", "docker/entrypoint.sh",
                "scripts/docker/bootstrap_identity.py", "scripts/docker/prefetch_model.py", "requirements-proxy.txt", "requirements-dev.txt"):
        assert (ROOT / rel).is_file(), rel


def test_shipped_compose_defaults_to_the_starter_policy_and_the_image_carries_it():
    env = COMPOSE["services"]["sentinel"]["environment"]
    assert env["SENTINEL_POLICY"] == "${SENTINEL_POLICY:-builtin:starter}"
    assert (ROOT / "server" / "policies" / "starter.json").is_file()
    assert "COPY server server" in (ROOT / "Dockerfile").read_text()
    assert not any(p in IGNORE for p in ("server/policies", "**/policies", "**/*.json", "policies"))
    assert "SENTINEL_POLICY" in (ROOT / ".env.example").read_text()
