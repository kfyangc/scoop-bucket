# Scoop Bucket 维护指南

本仓库是个人 Scoop bucket（`kfyangc/scoop-bucket`），远程为 SSH，master 直接提交。

## 添加新 manifest 的流程

1. **确定文件名**：与上游仓库名一致（如 `downkyicore.json` 对应 `crazysmile-PhD/downkyicore`）。
2. **收集信息**（GitHub API 匿名即可）：
   - `https://api.github.com/repos/<owner>/<repo>` — 取 `description`、`license.spdx_id`
   - `https://api.github.com/repos/<owner>/<repo>/releases?per_page=8` — **核对至少最近 5~8 个 release 的资产命名规律**，确认 autoupdate 的 URL 模板稳定（注意版本号前后缀，如 `DownKyi-$version-1.win-x64.zip` 中的 `-1` 是固定的）。
3. **计算哈希**：下载每个架构的包后 `sha256sum`。不要凭空填或抄网页上的值。
4. **查看压缩包结构**（本机无 `unzip`，用 PowerShell）：
   ```powershell
   Add-Type -AssemblyName System.IO.Compression.FileSystem
   [IO.Compression.ZipFile]::OpenRead('<windows路径>').Entries | Select-Object -ExpandProperty FullName
   ```
   确认主 exe 在压缩包中的位置，GUI 程序用 `shortcuts`，CLI 用 `bin`。
5. **参照现有 manifest 的风格**：4 空格缩进；字段顺序 version → description → homepage → license → architecture(url+hash) → shortcuts/bin → checkver → autoupdate。参考 `bucket/downkyicore.json`。

## 验证（推送前必做）

```bash
# 1. 语法与字段能被 scoop 解析
scoop info <name>

# 2. schema 校验（与 CI 相同的校验器；$SCOOP 为 scoop 安装目录，已设为全局环境变量）
powershell -NoProfile -Command "Add-Type -Path \"\$env:SCOOP/apps/scoop/current/supporting/validator/bin/Scoop.Validator.dll\"; \$v = New-Object Scoop.Validator(\"\$env:SCOOP/apps/scoop/current/schema.json\", \$true); \$v.Validate('bucket/<name>.json'); \$v.Errors | ForEach-Object { \$_.Message }; 'Valid: ' + \$v.Valid"
# 注意：schema.json 在 scoop 程序目录（apps/scoop/current），不在 test/ 下

# 3. 完整测试套件（需先 Install-Module Pester 5.2.0 和 BuildHelpers 2.0.1）
SCOOP_HOME="$SCOOP/apps/scoop/current" powershell -NoProfile -ExecutionPolicy Bypass -File bin/test.ps1
```

## 验证文件格式（推送前必做，防止 CI 失败）

新文件写入后统一转 CRLF（Git Bash 下用 sed，避免 PowerShell 内联转义出错）：

```bash
sed -i -e 's/\r*$/\r/' <文件>
```

## CI（Tests 工作流）的坑

CI 会检出全部文件并用 Pester 跑 `bin/test.ps1`（scoop core 的标准 bucket 测试）。除了 schema，还检查**仓库里所有文本文件**的编码/格式，任何一项不过整个 run 失败：

- **行首不允许 TAB**（`scripts/` 下的 shell 脚本也必须用空格缩进 —— 已有教训：`scripts/zedg/zed` 的 TAB 导致两次 CI 失败）
- **不能有 UTF-8 BOM**、**不能有行尾空格**、**文件必须以换行符结尾**
- 换行符要求 CRLF。仓库 `.gitattributes` 是 `* text=auto eol=crlf`：git index 里统一存 LF，CI 检出时自动转 CRLF。因此用 LF 写入的新文件在 CI 上通常能过，但**本地工作副本请保持 CRLF**（与其余 manifest 一致，避免本地测试误报）。`scripts/` 下需要在 WSL 里跑的 sh 脚本是例外，保留 LF（CI 检出时仍会被转为 CRLF，不影响 CI 通过，本地测试会对它报 CRLF 一项，可接受）。

## 提交规范

参照 git 历史：

- 新增：`Add <name> manifest`
- 更新：`<name>: Update to version <version>`

上游新版本由 Excavator 工作流每 4 小时自动检查并提交，日常不用手动跟版本；只需保证 manifest 的 `checkver`/`autoupdate` 写对。
