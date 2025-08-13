# pgit

A static site generator for git.

This golang binary will generate a commit log, files, and references based on a
git repository and the provided revisions.

It will only generate a commit log and files for the provided revisions.

### Features of this fork:

- Uses urfave/cli/v3
- Uses Chroma to identify languages
- Reads .gitattributes file, allowing to customize the languages bar
- Has search bar (requires JS. The search bar will not be displayed on hosts that don't support JS.)
- Has a config file

##### See it in action at: [git.xplshn.com.ar](https://git.xplshn.com.ar)
