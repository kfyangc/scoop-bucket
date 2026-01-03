# What will be put in this bucket?

Here are some Scoop buckets that I find useful:

```
main       https://gitee.com/scoop-bucket/main.git
extras     https://gitee.com/scoop-bucket/extras.git
versions   https://gitee.com/scoop-bucket/versions.git
nerd-fonts https://gitee.com/scoop-bucket/nerd-fonts.git
java       https://gitee.com/scoop-bucket/java.git
ar         https://github.com/arch3rPro/PST-Bucket
lemon      https://github.com/hoilc/scoop-lemon
abyss      https://gitee.com/abgox/abyss
extras-cn  https://gitee.com/scoop-installer/scoopet.git
zed        https://github.com/sonyxu/zed-loc-bucket
```

If apps are not available in the above buckets and I find them useful, I will add them in this bucket.

# Scoop Bucket Template

<!-- Uncomment the following line after replacing placeholders -->
<!-- [![Tests](https://github.com/<username>/<bucketname>/actions/workflows/ci.yml/badge.svg)](https://github.com/<username>/<bucketname>/actions/workflows/ci.yml) [![Excavator](https://github.com/<username>/<bucketname>/actions/workflows/excavator.yml/badge.svg)](https://github.com/<username>/<bucketname>/actions/workflows/excavator.yml) -->

Template bucket for [Scoop](https://scoop.sh), the Windows command-line installer.

## How do I use this template?

1. Generate your own copy of this repository with the "Use this template"
   button.
2. Allow all GitHub Actions:
   - Navigate to `Settings` - `Actions` - `General` - `Actions permissions`.
   - Select `Allow all actions and reusable workflows`.
   - Then `Save`.
3. Allow writing to the repository from within GitHub Actions:
   - Navigate to `Settings` - `Actions` - `General` - `Workflow permissions`.
   - Select `Read and write permissions`.
   - Then `Save`.
4. Document the bucket in `README.md`.
5. Replace the placeholder repository string in `bin/auto-pr.ps1`.
6. Create new manifests by copying `bucket/app-name.json.template` to
   `bucket/<app-name>.json`.
7. Commit and push changes.
8. If you'd like your bucket to be indexed on `https://scoop.sh`, add the
   topic `scoop-bucket` to your repository.

## How do I install these manifests?

After manifests have been committed and pushed, run the following:

```pwsh
scoop bucket add <bucketname> https://github.com/<username>/<bucketname>
scoop install <bucketname>/<manifestname>
```

## How do I contribute new manifests?

To make a new manifest contribution, please read the [Contributing
Guide](https://github.com/ScoopInstaller/.github/blob/main/.github/CONTRIBUTING.md)
and [App Manifests](https://github.com/ScoopInstaller/Scoop/wiki/App-Manifests)
wiki page.
