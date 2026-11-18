# Releasing

1. Set the same version in `src/output/report.zig` (`version`) and
   `build.zig.zon` (`.version`), merge to `main`.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
3. `.github/workflows/release.yml` checks that the tag matches both
   versions, runs the tests, builds the four static binaries, packages
   them with `packaging/package.sh` (deterministic tarballs and
   `SHA256SUMS`), publishes the GitHub release, then installs it with
   `install.sh` on Linux x86_64, Linux aarch64 and macOS arm64.
4. Update the Homebrew tap (https://github.com/mcaney006/homebrew-zigmap):

   ```sh
   sh packaging/homebrew/render-formula.sh v0.2.0 > ../homebrew-zigmap/Formula/zigmap.rb
   ```

   Commit and push it, then check with
   `brew install mcaney006/zigmap/zigmap && brew test zigmap`.

Release asset names do not contain the version (`zigmap-<arch>-<os>.tar.gz`),
so `releases/latest/download/...` always points at the newest release.
