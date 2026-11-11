# C 部分：使用、讲解和接入

## 负责的内容

- `vault.py`：命令行入口、参数、隐藏密码输入、错误输出和退出码。
- `entries.py`：添加、列出、查看、删除账号；不直接读写文件，不修改传入列表。
- `generator.py`：使用 `secrets` 的强密码生成器。
- `tests/test_cli.py`、`tests/test_entries.py`、`tests/test_generator.py`：C 的验证。
- 主 README：真实命令示例、为什么选择 `secrets`、安全边界。

A 的三个存储接口、密钥派生和文件格式保持原样，B 的 bonus 不包含在这次 C 交接中。

## 调用关系

用户命令 → `vault.main` 解析参数 → 隐藏输入主密码 → `storage.load_vault` 解锁 →
`entries` 在内存中操作 → 修改类命令调用 `storage.save_vault` 保存。

`gen` 直接调用 `generate_password`，不读取保险箱，也不需要主密码。
`init` 两次确认主密码后调用 `initialize_vault`。访问已有保险箱的命令每次只提示一次主密码；
保存时 A 会在内部重新验证，C 不缓存 AES 密钥。

## Mac 上运行

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
source .venv/bin/activate
python vault.py --help
python vault.py init
python vault.py add github --user alice
python vault.py list
python vault.py get github
python vault.py delete github
python vault.py gen --length 20
```

使用假账号演示。默认在当前目录创建 `vault.json`；再次 init 会报错，不会覆盖。
自选文件可用 `--file work/demo-vault.json`，父目录必须先创建。
指定网站密码时用 `add SITE --user USER --prompt-password`，会隐藏输入并要求确认。
不要把主密码或账号密码作为命令行参数传入。输入时不显示字符是正常行为。
`get` 输出完整账号 JSON，`list` 的 JSON 不包含密码；JSON 中的转义需要按 JSON 规则理解。

## 密码生成器为什么正确

`secrets.choice` 从操作系统提供的密码学安全随机源中选择字符。默认 `random` 生成器用于模拟，
当状态已知时可以预测后续输出，因此不适合生成真实密码。

字符池为 26 个小写字母、26 个大写字母、10 个数字和 32 个 ASCII 标点，共 94 个字符。
每次独立生成完整候选密码；若缺少任一字符组，就丢弃并重新生成。
这叫拒绝采样：从所有满足规则的候选字符串中均匀选取，不是用固定前缀凑字符类别。
默认 20 位，允许 12-1024 位，是本组的使用策略；课程只要求足够长、随机、字符集广及可选长度。
类别齐全本身不能替代安全随机性。更复杂的主密码仍要由用户自己选择，网站密码生成器不改变主密码。

## 出错时做什么

- 错误主密码、损坏文件、重复网站、不存在的记录、输入不合法：标准错误输出消息，退出码 1。
- 参数错误，例如长度不在范围、手动密码与生成长度同时指定：退出码 2。
- Ctrl+C：退出码 130；输入结束取消：退出码 1。
- 初始化确认不一致或手动密码确认不一致：不保存。
- 如果终端不能隐藏输入：拒绝操作，不退回可回显的输入。
- 出错后不清空、不重建保险箱。A 报“已保存但临时文件清理失败”时如实显示消息。

## 验证

```bash
.venv/bin/python -m unittest discover -s tests -v
```

C 的 36 项测试覆盖生成器、账号操作和 CLI。`test_cli.py` 既直接调用主入口并使用真实后端，
也在 Mac 伪终端中启动真正的 `vault.py` 子进程，验证隐藏输入和完整操作流程。
A 另有 36 项后端测试。最终完整结果见 `docs/C_VERIFICATION.md`。

C 收到文件后需要阅读并理解，再用自己的分支提交。这份材料用于解释实现，不应直接背结论。
