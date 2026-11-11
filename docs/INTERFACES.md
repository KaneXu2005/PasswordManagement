# Team integration contract — version 1

这是 A 已实现的接入约定，供 B、C 开发时采用；尚不表示其他组员已经确认。
变更函数签名、条目结构或文件格式前，三人应先同步，不能各改一套。

## Ownership

- A: `crypto.py`, `storage.py`, `errors.py`, backend tests and backend explanations.
- C: `vault.py`, `entries.py`, `generator.py`, CLI tests and usage documentation.
- B: `sharing.py`, `breach_check.py`, bonus tests and explanations.
- Everyone: understand the crypto, review README and complete final acceptance.

A 的后端和 C 的主体 CLI 已实现；B 的 bonus 仍待接入。C 的代码在本地交接分支中准备，交给 C 理解、检查后由其自己的分支提交。

## Public storage API

```python
from storage import initialize_vault, load_vault, save_vault

initialize_vault(path, master_password)          # -> None; create encrypted []
entries = load_vault(path, master_password)     # -> list[dict[str, str]]
save_vault(path, master_password, entries)      # -> None; replace ALL entries
```

- `path`: `str` 或 `pathlib.Path`，由 C 提供。C 的 CLI 默认可用当前工作目录的 `vault.json`；显式路径参数由 C 实现。
- `master_password`: 可编码为 UTF-8 的非空 `str`。A 不读取终端、不调用 `input()` 或 `getpass()`、不打印密码。
- C 应使用 `getpass.getpass()` 隐藏主密码输入；初始化时输入两次确认。不要用命令行参数传主密码，也不要 `strip()` 修改密码。
- 初始化已存在文件会失败，绝不覆盖；父目录必须已存在。
- 读取必须先验证主密码，再派生密钥，再认证解密。成功才返回完整条目。
- 保存先验证条目，再验证并解密已有保险箱，最后完整替换条目列表。它不负责合并、不自动创建文件，也不更换主密码。
- 保存用新的随机 nonce；失败不应被调用方当成成功。应用层不得捕获错误后重建或清空保险箱。
- 不返回、保存或缓存加密密钥；每次调用读取／保存时重新验证主密码。没有持久解锁会话。
- 仅支持顺序操作。C 必须串行执行“读—改—写”，不能让多个进程同时写同一个文件；当前没有并发冲突检测或合并。

## Entry format

```json
[
  {"site": "github", "username": "alice", "password": "example-only-password"}
]
```

- 顶层必须为列表，可为空。每条只允许这三个字段，值都为非空字符串。
- `site`、`username` 不能全为空白；支持有效的 UTF-8 Unicode 文本，拒绝孤立代理码点，A 不自动修改字段值。
- v1 每个 `site` 一条记录，按字符串精确匹配，区分大小写。
- C 添加重复 `site` 时应明确拒绝；如以后增加更新命令，由 C 找到原条目再修改。
- 不支持同一网站多个账号，也不支持 `notes`、`id` 等额外字段；需要时共同修订协议。
- 列出账号建议仅显示网站和用户名；只有显式 `get` 才显示密码。

C 的调用顺序：load → 在内存中 add/delete/update → save。list/get 只 load，无需 save。
C 的随机密码生成器输出普通 `str`，由 C 放入条目的 `password` 字段。

B 分享时：通过 load 取出用户指定的一条记录，仅序列化该记录后用接收者公钥加密。
不要分享主密码、AES 密钥、完整保险箱或主密码哈希。分享格式由 B 单独定义。
B 的非对称私钥属于选做分享功能，不是用于解锁保险箱的 AES 密钥文件。
B 查询泄露时：对选定密码计算 SHA-1，仅向 HIBP 发送前 5 个十六进制字符，在本地匹配返回后缀。
四项必做验收通过后再把选做接入 CLI。

## Error contract

所有可预期的保险箱错误继承 `errors.VaultError`，C 可以统一捕获并显示消息。命令成功时退出码为 0；失败时向标准错误输出清楚的消息并返回非零退出码。尤其不能将篡改错误转换为空列表、静默成功或自动重建保险箱，确保满足原文的明确报错要求。

| Exception | Meaning / CLI action |
| --- | --- |
| `InvalidMasterPassword` | 密码不匹配（也可能是验证哈希被改）；拒绝访问 |
| `VaultIntegrityError` | GCM 认证失败；拒绝返回数据，提示文件可能被修改 |
| `VaultFormatError` | 文件损坏、编码错误、字段或版本／参数不支持；拒绝访问 |
| `VaultAlreadyExistsError` | 初始化目标已存在；不覆盖 |
| `VaultNotFoundError` | 目标不存在；提示先初始化 |
| `VaultIOError` | 无法读取／写入，或已保存但临时文件无法清理；显示具体消息，检查路径或权限 |
| `EntryValidationError` | 条目结构不合约定或超出文件大小限制；修正输入 |

非字符串、空主密码或无法编码为 UTF-8 的主密码属于接口参数错误，抛出 `ValueError`，C 应在交互层先检查。
错误不包含主密码、密钥或账号明文。不要在日志中打印这些值。

## On-disk format (A owns it)

```json
{
  "version": 1,
  "master_hash": "$argon2id$v=19$m=65536,t=3,p=4$...$...",
  "kdf": {
    "name": "argon2id", "version": 19,
    "time_cost": 3, "memory_cost": 65536, "parallelism": 4,
    "length": 32, "salt": "<Base64: 16 random bytes>"
  },
  "nonce": "<Base64: 12 random bytes>",
  "ciphertext": "<Base64: encrypted entries followed by 16-byte GCM tag>"
}
```

- 主密码验证哈希自带随机盐；KDF 盐独立生成，两者用途分离。密钥是从主密码和 KDF 盐派生，不是从磁盘上的验证哈希取得。
- v1 固定 Argon2id 参数（内存为 KiB）和 AES-256-GCM。读入时先限制参数，避免恶意文件诱导超量 Argon2 运算。
- `version`、`master_hash`、`kdf` 的规范化 JSON（键排序、UTF-8、无额外空格）作为 GCM AAD，认证公共头部。
- nonce 和密文／标签发生修改会使解密失败；头部修改会被格式检查、主密码验证或认证检查拒绝。
- 为对齐课程“文件改一个字节就应报错”的验收，v1 固定外层 JSON 编码：UTF-8、键排序、两空格缩进、末尾一个换行。排版、键顺序、转义或末尾换行变化也会被格式检查拒绝；字段值和密文的完整性由 AES-GCM 验证。禁止手工编辑或重新格式化保险箱。
- A 的最终 v1 已在提交 `e7fd308` 中固定为上述编码。更早的本地草案文件不保证可读，不能通过捕获错误后重新初始化来迁移真实数据。C 沿用该格式，不修改 A 的三个存储接口。
- 文件最大 16 MiB；拒绝未知字段、重复 JSON 字段、无效 Base64 和不支持的版本。参数升级需要显式设计新版本／迁移，不能静默修改 v1。
- 同目录临时文件只包含加密文件内容；完成写入后原子替换。初始化使用原子硬链接发布，目标已存在时失败。
- 临时文件通常自动清理；若清理也失败，可能留下加密的 `.tmp` 文件。主保存失败时保留原始错误；若文件已发布而清理失败，`VaultIOError` 消息明确写出 `Vault was saved`。C 应显示具体消息，不能自动重试初始化或清空保险箱。
- 临时文件和保险箱在 POSIX 上权限为 0600。Windows 应另用系统 ACL 保护文件。
- C 和 B 不直接读写、修改以上字段，统一调用 storage API。

## C's implemented API and commands

- `entries.add_entry(entries, site, username, password)` returns a new complete list.
- `entries.list_entries(entries)` returns sorted site/username summaries, omitting passwords.
- `entries.get_entry(entries, site)` returns a detached complete entry.
- `entries.delete_entry(entries, site)` returns a new list without that site.
- `entries.EntryNotFoundError` inherits `VaultError`; missing get/delete is an error.
- `generator.generate_password(length=20)` returns a secure password. Length is an integer in 12-1024; each candidate must contain lowercase, uppercase, digits and symbols.
- Entry operations reuse A's existing `crypto.validate_entries` for the data contract; they never call crypto primitives or access the vault file directly.

CLI: `init`, `add SITE --user USER`, `list`, `get SITE`, `delete SITE`, `gen --length N`.
`add` defaults to generation; `--length N` sets generated length; mutually exclusive
`--prompt-password` requests hidden manual entry and confirmation. `--file PATH`
works before or after the subcommand. Init confirms the master password. Each
vault-access command prompts once for the master password; `gen` does not unlock.
List/get return JSON. Use a real terminal; unsafe echoing input fallback is rejected.

Success exits 0, operation/input failure exits 1, argument error exits 2, Ctrl+C
exits 130. C does not implement B's subcommands or network requests. B can extend
`vault._build_parser` and `vault._run` while retaining these existing command/error
behaviors and A's storage API. Detailed usage is in the main README.
