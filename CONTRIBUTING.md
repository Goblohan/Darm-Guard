# Contributing

Contributions are welcome under the project's license (Apache-2.0, see LICENSE).

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org):
by adding a `Signed-off-by: Your Name <you@example.com>` line (`git commit -s`), you certify that you
wrote the contribution or otherwise have the right to submit it under the project's license.

Before opening a pull request, run the project's gate and include its result:
`scripts/gate.sh` in darm-monitor, `scripts/ci_local.py` in Darm-Guard. Every claim the project makes
is checked by them; a change that weakens a check needs to say so, and why.
