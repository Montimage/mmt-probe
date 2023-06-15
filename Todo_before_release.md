Before creating a new release, you need:
- check whether mmt-probe works correctly
- update `CHANGLOG.md` within the new features of this release
- update `VERSION` value in the `Makefile` to reflex the new version of the release
- create a new tag within the name is prefix `v` before the version number, for example, `v1.5.12`
- push the modification above and the tag to GitHub. A new container will be built and created automatically for this release.