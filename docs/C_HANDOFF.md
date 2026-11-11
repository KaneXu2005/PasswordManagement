# C 的交接说明

本包是 C 部分的源文件和说明，基于 A 的提交 `e7fd308`。
开发和验证目标是 Mac。代码由本次协作准备，C 收到后应阅读、理解并检查，再用自己的账号提交。
没有为 C 创建提交、伪造作者信息或推送分支。

## 包里有什么

- `files/`：按项目相对路径放好的新增／修改文件，复制其内部内容到项目根目录。
- `SHA256SUMS.txt`：`files/` 内每个文件的 SHA-256，用于核对传输内容。
- `BASE_COMMIT.txt`：所需 A 基线的完整提交编号。
- `START_HERE.txt`：Windows 可直接打开的简明操作单，先读这一份。
- `START_HERE.md`：本说明的独立副本，包含详细解释。

不包含 `.git`、`.venv`、真实账号、保险箱、私钥或 B 的代码。
只复制清单文件，不要用一个空目录替换整个仓库；保留现有 B 模块。

## C 的 Windows 和已有本地分支流程

C 已经有名为 `Enzo` 的本地分支，远端还没有对应分支，这是正常情况。继续使用 `Enzo`，
不必重新创建分支，也不必提前在 GitHub 上创建远端分支。注意保留首字母大写。以下 Git 命令可在 Windows
PowerShell、Git Bash 或终端中执行；最终运行展示仍在 Mac 上。

### 1. 在现有 C 分支引入 A 的代码

进入 C 自己的项目仓库，先妥善保存已有的未提交修改，再切换并检查：

```powershell
git switch Enzo
git branch --show-current
git status --short
```

`git branch --show-current` 的输出应为 `Enzo`。后续合并、复制、提交操作都在 `Enzo` 分支完成。
工作区如果有未提交修改，应先妥善保存。

在 `Enzo` 分支上执行：

```powershell
git fetch origin
git merge origin/jim
```

这会将 A 已推送的代码合并进 C 当前分支，不会把 C 的分支重命名为 jim。
出现冲突时先解决并完成合并，再复制交接文件。

### 2. 复制和检查 C 的交接文件

1. 解压压缩包，将 `files/` 里面的内容按相对路径复制到项目根目录；不是复制 `files` 这个外层文件夹。
2. 阅读 `docs/C_GUIDE.md` 和 README，查看代码差异。README 与部分共享说明有更新，保留团队其他成员已补充的内容。
3. 本次已在 Mac 上验证全部 72 项测试。Windows 不作为最终运行目标，不要求 C 为提交另行完成 Windows 测试；最终仍应在展示 Mac 上演练。
4. 仅添加本包清单中的源文件、测试和说明，检查后提交。不要复制或提交虚拟环境、保险箱、整个 `.git` 目录。

Mac 完整测试命令（供实际展示电脑使用）：

```bash
.venv/bin/python -m unittest discover -s tests -v
```

### 3. 在 C 现有分支提交，然后首次推送

```powershell
git add vault.py entries.py generator.py tests/test_cli.py tests/test_entries.py tests/test_generator.py README.md .gitignore docs/C_GUIDE.md docs/C_VERIFICATION.md docs/C_HANDOFF.md docs/INTERFACES.md docs/A_GUIDE.md docs/VERIFICATION.md docs/REQUIREMENTS_CHECK.md
git diff --cached --stat
git commit -m "feat: add CLI account management and secure password generation"
git push -u origin Enzo
```

最后一行会在 origin 创建远端 `Enzo` 分支并建立跟踪关系；之后在 `Enzo` 分支上可直接
`git push`。分支名按 `Enzo` 的大小写输入。

推送后创建 `Enzo` 到 `main` 的 Pull Request。main 尚未包含 A 时，应先合并 A 的 PR，
再合并 C 的 PR，便于查看各自贡献。交接包本身不需要提交到仓库。

## 完成范围

C 的初始化、账号 add/list/get/delete、强密码生成、隐藏输入和错误处理已实现。
A 的 `crypto.py`、`storage.py`、`errors.py`、`requirements.txt` 和 `tests/test_backend.py` 没有修改。
接口仍为 `initialize_vault / load_vault / save_vault`。B 的 bonus 仍待接入。
详细实际验证结果见 `docs/C_VERIFICATION.md`。
