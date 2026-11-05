Before creating a new release, you need:
- check whether mmt-probe works correctly
- update `CHANGLOG.md` within the new features of this release
- update `VERSION` value in the `Makefile` to reflex the new version of the release
- update `DPI_VERSION` and `SECURITY_VERSION` in `./script/install-from-source.sh` to tell which versions of DPI and Security will be included in the released packages
- create a new tag within the name is prefix `v` before the version number, for example, `v1.5.12`
- push the modification above and the tag to GitHub. New containers will be built and created automatically for this release.