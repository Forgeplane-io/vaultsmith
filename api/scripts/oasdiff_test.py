import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


LAUNCHER = Path(__file__).with_name("oasdiff.sh")
DARWIN_MAX_ARCHIVE_BYTES = 16_777_216


class OasdiffLauncherTest(unittest.TestCase):
    def write_executable(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def test_rejects_an_oversized_download_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            cache = root / "cache"
            fake_bin.mkdir()
            curl_args = root / "curl-args"
            hash_marker = root / "hash-called"

            self.write_executable(
                fake_bin / "uname",
                """#!/bin/sh
case "$1" in
  -s) printf 'Darwin\\n' ;;
  -m) printf 'arm64\\n' ;;
  *) exit 2 ;;
esac
""",
            )
            self.write_executable(
                fake_bin / "curl",
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import pathlib
                    import sys

                    arguments = sys.argv[1:]
                    pathlib.Path({str(curl_args)!r}).write_text("\\n".join(arguments), encoding="utf-8")
                    output = pathlib.Path(arguments[arguments.index("-o") + 1])
                    with output.open("wb") as stream:
                        stream.truncate({DARWIN_MAX_ARCHIVE_BYTES + 1})
                    """
                ),
            )
            self.write_executable(
                fake_bin / "sha256sum",
                f"""#!/bin/sh
: > {str(hash_marker)!r}
printf '%064d  %s\\n' 0 "$1"
""",
            )
            self.write_executable(fake_bin / "tar", "#!/bin/sh\nexit 99\n")

            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join((str(fake_bin), "/usr/bin", "/bin"))
            environment["OASDIFF_CACHE_DIR"] = str(cache)
            result = subprocess.run(
                ["/bin/bash", str(LAUNCHER), "version"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("configured max 16777216", result.stderr)
            self.assertIn("observed 16777217", result.stderr)
            self.assertIn("--max-filesize\n16777216", curl_args.read_text(encoding="utf-8"))
            self.assertFalse(hash_marker.exists(), "oversized archive was hashed")
            self.assertFalse((cache / "oasdiff_1.28.0_darwin_all.tar.gz").exists())

    def test_rejects_an_oversized_cache_entry_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            cache = root / "cache"
            fake_bin.mkdir()
            cache.mkdir()
            hash_marker = root / "hash-called"
            tar_marker = root / "tar-called"
            curl_marker = root / "curl-called"
            archive = cache / "oasdiff_1.28.0_darwin_all.tar.gz"
            with archive.open("wb") as stream:
                stream.truncate(DARWIN_MAX_ARCHIVE_BYTES + 1)

            self.write_executable(
                fake_bin / "uname",
                """#!/bin/sh
case "$1" in
  -s) printf 'Darwin\\n' ;;
  -m) printf 'arm64\\n' ;;
  *) exit 2 ;;
esac
""",
            )
            self.write_executable(
                fake_bin / "curl",
                f"""#!/bin/sh
: > {str(curl_marker)!r}
exit 98
""",
            )
            self.write_executable(
                fake_bin / "sha256sum",
                f"""#!/bin/sh
: > {str(hash_marker)!r}
printf '%064d  %s\\n' 0 "$1"
""",
            )
            self.write_executable(
                fake_bin / "tar",
                f"""#!/bin/sh
: > {str(tar_marker)!r}
exit 99
""",
            )

            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join((str(fake_bin), "/usr/bin", "/bin"))
            environment["OASDIFF_CACHE_DIR"] = str(cache)
            result = subprocess.run(
                ["/bin/bash", str(LAUNCHER), "version"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("configured max 16777216", result.stderr)
            self.assertIn("observed 16777217", result.stderr)
            self.assertFalse(curl_marker.exists(), "cached archive triggered a download")
            self.assertFalse(hash_marker.exists(), "oversized cache entry was hashed")
            self.assertFalse(tar_marker.exists(), "oversized cache entry was extracted")


if __name__ == "__main__":
    unittest.main()
