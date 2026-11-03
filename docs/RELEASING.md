# Releasing to PyPI

Segurai is published by GitHub Actions, using **trusted publishing**: PyPI trusts one workflow in one repository, so no API token is stored anywhere. After the one-time setup below, a release is a git tag.

---

## One-time setup on PyPI (about two minutes)

The project doesn't exist on PyPI yet, so you add a *pending* publisher: permission to create it on first upload.

1. Sign in to PyPI and turn on two-factor authentication if you haven't (PyPI requires it for publishing).
2. Go to **<https://pypi.org/manage/account/publishing/>**.
3. Under "Add a new pending publisher", choose **GitHub** and fill in exactly:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `segurai` |
   | Owner | `Yaxomiller` |
   | Repository name | `segurai` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

4. Click **Add**.

That's the whole setup. Nothing is pasted into this repository, and there's no token to rotate or leak.

---

## Cutting a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

That starts [the Release workflow](https://github.com/Yaxomiller/segurai/actions/workflows/release.yml), which:

1. runs lint, the full test suite and the Tier 1 scenario suite — a tag that fails is never published;
2. checks the tag matches the version in `src/segurai/_version.py`, so `v0.2.0` can't publish a package that
   still says `0.1.0`. It reads that file on its own rather than importing `segurai`, because the build job
   installs no dependencies;
3. builds the wheel and source distribution and runs `twine check --strict`;
4. uploads to PyPI.

Then check <https://pypi.org/project/segurai/> and, in a clean environment:

```bash
pip install segurai
segurai --help
```

## Releasing a later version

1. Bump the version in `src/segurai/_version.py` (that single file is the source of truth; `pyproject.toml` reads it).
2. Move the `CHANGELOG.md` entries under a new heading with the version and date.
3. Commit, then tag with a matching `vX.Y.Z` and push the tag.

## If a release fails

Nothing is published unless every step passes, so a failed run is safe — fix the cause, then move the tag and push it again:

```bash
git tag -d v0.1.0
git push origin :refs/tags/v0.1.0
git tag -a v0.1.0 -m "Segurai 0.1.0"
git push origin v0.1.0
```

Reusing a version number is only safe while PyPI has never accepted it: PyPI refuses to overwrite a released version. If the upload itself succeeded and something else was wrong, bump to the next version instead.

## If you'd rather upload by hand

Trusted publishing is the better default, but a token works too. Create one at <https://pypi.org/manage/account/token/>, then:

```bash
python -m pip install build twine
python -m build
python -m twine upload dist/*
```

Use `__token__` as the username and the token (including the `pypi-` prefix) as the password. Keep it in a password manager, not in a file in the repository. After the first upload, replace it with a token scoped to the `segurai` project alone.

## Pre-release checks

Everything here is already enforced by CI, but before a first release it's worth seeing for yourself:

```bash
python -m pytest -q                 # 296 tests
python -m build                     # wheel + sdist
python -m twine check --strict dist/*
```
