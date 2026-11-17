"""The Landlock rights arithmetic as pure functions (no kernel, no process): which access bits a rule gets for a path or an exact grant.

Grants are `read` (READ_FILE on exactly that file), `list` (READ_DIR beneath that directory) and, from phase 2 (DECISIONS D32), `write`
(READ_FILE | WRITE_FILE | TRUNCATE on exactly one existing regular file, ABI >= 3). No grant ever carries EXECUTE, MAKE_*, REMOVE_*, REFER or
IOCTL_DEV, and only `write` carries WRITE_FILE / TRUNCATE. The expected values below are literal kernel bit numbers (include/uapi/linux/landlock.h), not the module's own constants,
so a change to a constant cannot make the test agree with itself."""
import pytest

from sentinel_proxy import sandbox

# literal LANDLOCK_ACCESS_FS_* bits
EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 0x1, 0x2, 0x4, 0x8
REMOVE_DIR, REMOVE_FILE = 0x10, 0x20
MAKE_CHAR, MAKE_DIR, MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM = 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000
REFER, TRUNCATE, IOCTL_DEV = 0x2000, 0x4000, 0x8000
ALL_MAKE = MAKE_CHAR | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM
MUTATING = WRITE_FILE | REMOVE_DIR | REMOVE_FILE | ALL_MAKE | REFER | TRUNCATE


# --------------------------------------------------------------------------- the grant vocabulary


def test_the_grant_rights_are_exactly_read_list_and_write():
    assert sandbox.GRANT_RIGHTS == {"read": READ_FILE, "list": READ_DIR, "write": READ_FILE | WRITE_FILE | TRUNCATE}


@pytest.mark.parametrize("right", ["w", "rw", "read|write", "READ", "WRITE", "", "execute", "delete", "create", "append", "truncate", "overwrite"])
def test_no_other_grant_right_exists(right):
    assert right not in sandbox.GRANT_RIGHTS


def test_only_the_write_grant_carries_a_mutating_bit_and_it_is_exactly_write_file_and_truncate():
    for name, bits in sandbox.GRANT_RIGHTS.items():
        assert not bits & (EXECUTE | IOCTL_DEV | REMOVE_DIR | REMOVE_FILE | ALL_MAKE | REFER), name
        assert bits & MUTATING == (WRITE_FILE | TRUNCATE if name == "write" else 0), name


def test_the_write_grant_needs_landlock_abi_3_because_below_it_truncate_is_not_mediated():
    assert sandbox.WRITE_MIN_ABI == 3
    assert [sandbox.write_abi_ok(a) for a in range(0, 9)] == [False, False, False, True, True, True, True, True, True]


@pytest.mark.parametrize("abi, expected", [(1, READ_FILE | WRITE_FILE), (2, READ_FILE | WRITE_FILE),
                                           (3, READ_FILE | WRITE_FILE | TRUNCATE), (4, READ_FILE | WRITE_FILE | TRUNCATE),
                                           (5, READ_FILE | WRITE_FILE | TRUNCATE), (6, READ_FILE | WRITE_FILE | TRUNCATE),
                                           (7, READ_FILE | WRITE_FILE | TRUNCATE)])
def test_a_write_grant_on_a_file_per_abi(abi, expected):
    """Below ABI 3 the TRUNCATE bit is dropped (the kernel does not know it); the grant is then refused as a whole by `write_abi_ok`."""
    assert sandbox.rule_access(sandbox.GRANT_RIGHTS["write"], abi, is_dir=False) == expected


@pytest.mark.parametrize("abi", range(1, 8))
def test_a_write_grant_never_has_execute_make_remove_refer_or_ioctl_bits_at_any_abi(abi):
    got = sandbox.rule_access(sandbox.GRANT_RIGHTS["write"], abi, is_dir=False)
    assert got & ~(READ_FILE | WRITE_FILE | TRUNCATE) == 0


# --------------------------------------------------------------------------- fs_mask: what each ABI handles


@pytest.mark.parametrize("abi, expected", [
    (1, 0x1FFF),
    (2, 0x1FFF | REFER),
    (3, 0x1FFF | REFER | TRUNCATE),
    (4, 0x1FFF | REFER | TRUNCATE),
    (5, 0x1FFF | REFER | TRUNCATE | IOCTL_DEV),
    (7, 0x1FFF | REFER | TRUNCATE | IOCTL_DEV),
])
def test_the_handled_mask_per_abi(abi, expected):
    assert sandbox.fs_mask(abi) == expected


# --------------------------------------------------------------------------- rule_access: one rule's bits


@pytest.mark.parametrize("abi", range(1, 8))
def test_a_read_grant_on_a_file_is_read_file_and_nothing_else(abi):
    assert sandbox.rule_access(sandbox.GRANT_RIGHTS["read"], abi, is_dir=False) == READ_FILE


@pytest.mark.parametrize("abi", range(1, 8))
def test_a_list_grant_on_a_directory_is_read_dir_and_nothing_else(abi):
    assert sandbox.rule_access(sandbox.GRANT_RIGHTS["list"], abi, is_dir=True) == READ_DIR


@pytest.mark.parametrize("abi", range(1, 8))
def test_a_directory_right_on_a_file_gives_no_rule_never_a_wider_one(abi):
    """`list` on a file, or any directory-only bit on a file: masked to nothing (the caller adds no rule), not widened to a file right."""
    assert sandbox.rule_access(READ_DIR, abi, is_dir=False) == 0
    assert sandbox.rule_access(sandbox.GRANT_RIGHTS["list"], abi, is_dir=False) == 0
    assert sandbox.rule_access(REMOVE_DIR | REMOVE_FILE | ALL_MAKE | REFER | READ_DIR, abi, is_dir=False) == 0


@pytest.mark.parametrize("abi", range(1, 8))
def test_a_file_right_on_a_directory_is_kept(abi):
    assert sandbox.rule_access(READ_FILE, abi, is_dir=True) == READ_FILE


@pytest.mark.parametrize("abi, expected_dir, expected_file", [
    (1, 0x1FFF & ~EXECUTE, WRITE_FILE | READ_FILE),
    (2, (0x1FFF | REFER) & ~EXECUTE, WRITE_FILE | READ_FILE),
    (3, (0x1FFF | REFER | TRUNCATE) & ~EXECUTE, WRITE_FILE | READ_FILE | TRUNCATE),
    (7, (0x1FFF | REFER | TRUNCATE) & ~EXECUTE, WRITE_FILE | READ_FILE | TRUNCATE),
])
def test_the_write_set_per_abi_for_a_directory_and_for_a_file(abi, expected_dir, expected_file):
    """The operator's `write` directories (never a confined worker's grants): everything but EXECUTE the ABI knows; TRUNCATE only from ABI 3,
    REFER only from ABI 2 (a bit the kernel does not know is dropped, never passed through)."""
    assert sandbox.rule_access(sandbox._WRITE_RIGHTS, abi, is_dir=True) == expected_dir
    assert sandbox.rule_access(sandbox._WRITE_RIGHTS, abi, is_dir=False) == expected_file


@pytest.mark.parametrize("abi", range(1, 8))
def test_the_read_set_for_a_directory_and_for_a_file(abi):
    assert sandbox.rule_access(sandbox._READ_RIGHTS, abi, is_dir=True) == READ_FILE | READ_DIR | EXECUTE
    assert sandbox.rule_access(sandbox._READ_RIGHTS, abi, is_dir=False) == READ_FILE | EXECUTE


@pytest.mark.parametrize("abi", range(1, 8))
@pytest.mark.parametrize("is_dir", [True, False])
def test_the_result_is_always_a_subset_of_what_was_asked_and_of_what_the_abi_handles(abi, is_dir):
    for rights in (sandbox._READ_RIGHTS, sandbox._WRITE_RIGHTS, 0xFFFF, 0, READ_FILE, REFER, TRUNCATE, IOCTL_DEV, 1 << 20):
        got = sandbox.rule_access(rights, abi, is_dir=is_dir)
        assert got & ~rights == 0 and got & ~sandbox.fs_mask(abi) == 0
        if not is_dir:
            assert got & ~(EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV) == 0


def test_a_right_the_kernel_does_not_know_is_dropped_not_passed_on():
    assert sandbox.rule_access(1 << 20, 7, is_dir=True) == 0 and sandbox.rule_access(1 << 20, 7, is_dir=False) == 0
    assert sandbox.rule_access(TRUNCATE, 2, is_dir=False) == 0          # TRUNCATE is ABI 3
    assert sandbox.rule_access(REFER, 1, is_dir=True) == 0              # REFER is ABI 2


# --------------------------------------------------------------------------- fs_rules: what a spec gets


def spec(**kw):
    base = {"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True}
    return {**base, **kw}


def rules_of(**kw):
    return dict(sandbox.fs_rules(spec(**kw), "/home/h"))


def test_read_runtime_write_and_home_rights():
    r = rules_of(read=["/data/r"], write=["/data/w"], runtime=["/opt/rt"])
    assert r["/data/r"] == READ_FILE | READ_DIR | EXECUTE
    assert r["/opt/rt"] == READ_FILE | READ_DIR | EXECUTE
    assert r["/data/w"] == sandbox._WRITE_RIGHTS and not r["/data/w"] & EXECUTE
    assert r["/home/h"] == sandbox._WRITE_RIGHTS                       # the private HOME: the worker's only writable place
    assert r["/dev/null"] == READ_FILE | WRITE_FILE | TRUNCATE
    assert r["/dev/zero"] == r["/dev/urandom"] == READ_FILE


def test_a_read_path_never_gets_a_mutating_bit():
    for p, bits in sandbox.fs_rules(spec(read=["/data/r"], runtime=["/opt/rt"]), "/home/h"):
        if p in ("/data/r", "/opt/rt", *sandbox.SYSTEM_READ):
            assert not bits & MUTATING, p


def test_a_confined_spec_has_no_data_rule_at_all_only_the_system_runtime_and_home():
    from sentinel_proxy import confine
    s = confine.confined_spec(spec(read=["/data/r"], write=["/data/w"], runtime=["/opt/rt"]), [["/", "/data/r/a.txt", "read"]])
    paths = {p for p, _ in sandbox.fs_rules(s, "/home/h")}
    assert "/data/r" not in paths and "/data/w" not in paths and "/opt/rt" in paths and "/home/h" in paths


def test_write_rights_exist_only_for_home_dev_null_and_the_operators_write_dirs():
    writers = {p for p, bits in sandbox.fs_rules(spec(read=["/r"], write=["/w"], runtime=["/rt"]), "/home/h") if bits & MUTATING}
    assert writers == {"/w", "/home/h", "/dev/null"}


def test_network_hosts_files_are_read_only_rules():
    r = dict(sandbox.fs_rules(spec(network="loopback"), "/home/h"))
    assert r["/etc/hosts"] == READ_FILE | READ_DIR | EXECUTE and not r["/etc/hosts"] & MUTATING


# --------------------------------------------------------------------------- restrict_landlock refuses before touching the kernel


def test_restrict_landlock_refuses_abi_zero_and_tcp_rules_below_abi_4():
    with pytest.raises(OSError):
        sandbox.restrict_landlock(0, [], deny_tcp=False)
    for abi in (1, 2, 3):
        with pytest.raises(OSError, match="ABI 4"):
            sandbox.restrict_landlock(abi, [], deny_tcp=True)
