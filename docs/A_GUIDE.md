# A 部分：理解、验证与交接

## 你的交付范围

A 实现了三个必做模块：主密码的 Argon2id 哈希与验证、用 Argon2id 派生 AES 密钥、AES-GCM 保险箱加密，以及必要的文件存储。
C 的命令行、账号增删查和 `secrets` 密码生成器现已实现，使用说明见主 README 和 `docs/C_GUIDE.md`；B 的 bonus 尚待接入。本文聚焦 A 的代码。

## 在项目目录运行

需要 Python 3.9+，在 PasswordManagement 目录执行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Windows 对应使用 `.venv\Scripts\python.exe`。自动测试只用虚构账号；临时文件在本项目 `work/` 内并自动清理。

## 不依赖 C 的命令行，手动验证接口

在项目目录执行 `.venv/bin/python`，进入 Python 交互环境，然后输入：

```python
from pathlib import Path
from getpass import getpass
from storage import initialize_vault, load_vault, save_vault

Path("work").mkdir(exist_ok=True)
path = Path("work/manual-vault.json")
master = getpass("Test master password: ")
initialize_vault(path, master)
load_vault(path, master)  # []
entries = [{"site": "github", "username": "alice", "password": "fake-test-password!"}]
save_vault(path, master, entries)
load_vault(path, master)  # returns the fake entry
```

关闭解释器再打开，用相同路径和重新输入的主密码调用 load，仍应取回数据。重复 init 会被拒绝；用错主密码也会被拒绝。
仅使用测试密码，手动验证后删除 `work/manual-vault.json`。不要用 Python 的 print 输出真实密码，也不要把真实密码直接写进命令历史。

## 你要能解释的流程

初始化：生成 Argon2id 验证哈希 → 生成独立 KDF 盐 → 从主密码派生 32 字节密钥 → 用新的 12 字节 nonce 加密空列表 → 保存公共参数和密文。

读取：检查固定 JSON 编码、格式和参数 → 验证主密码 → 用同一个 KDF 盐重算密钥 → AES-GCM 验证认证标签和头部 → 返回账号列表。

保存：检查新条目 → 解锁并认证旧文件 → 用全新 nonce 加密新列表 → 写加密临时文件 → 原子替换。

## README 中 A 负责的解释

1. **为什么用 Argon2id，而不是 SHA-256 或 AES 保存主密码？**
   SHA-256 为快速计算设计，单独用于密码验证会让攻击者高速猜测。Argon2id 有时间和内存成本，提高每次猜测的代价；随机盐防止相同密码产生相同记录，并削弱预计算攻击。AES 是可逆加密，需要保护另一把密钥，不适合作为主密码验证的替代方案。Argon2id 仍不能把弱密码变强。
2. **为什么从主密码派生密钥？**
   如果随机 AES 密钥以明文文件放在保险箱旁边，攻击者拿到两者就能解密。这里磁盘只保存 KDF 盐和参数，每次需要主密码才能重算密钥。磁盘上的验证哈希不是 AES 密钥，绝不把它直接当密钥使用。
3. **为什么用 AES-GCM？**
   加密提供机密性；GCM 的认证标签帮助发现密文被改。只有认证通过，程序才解析和返回明文。AAD 把公共头部也绑定到标签。外层 JSON 固定编码，额外拒绝排版／键顺序等修改，以对齐课程的文件篡改验收；这是格式校验，不能替代 AES-GCM 的认证。nonce 不保密，但同一密钥下必须避免重复，本程序每次加密随机生成 96 位 nonce，适用于这个小型本地项目；随机生成不提供数学上的绝不碰撞保证。
4. **参数为什么这样选？**
   Argon2id 使用 64 MiB、3 次迭代、4 路并行、16 字节盐、32 字节输出，采用 argon2-cffi 文档中的 RFC 9106 低内存配置。哈希验证和 KDF 使用不同盐；KDF 输出用于 AES-256。版本 1 固定参数，使解锁可复现，也避免随库默认值变化而误读文件。目标电脑仍需确认内存和运行时间可接受。
5. **有哪些限制？**
   文件被窃取后仍可能遭到离线猜测，强主密码很重要。无法防御键盘记录器、恶意软件、屏幕窥视或已经解锁时的内存读取。Python 不保证可靠清除字符串和字节对象的内存；操作系统的交换区／崩溃转储也不在本工具的控制范围。不能检测旧的有效保险箱被回滚替换，也不提供多进程并发写入或断电恢复保证。忘记主密码没有恢复后门。

以上是理解材料。提交前用自己的语言整理 README，并练习指着代码解释，而不只是背结论。

## 重点代码位置

- `crypto.hash_master_password` / `verify_master_password`: 创建与验证 Argon2id 哈希。
- `crypto.derive_key`: Argon2id raw KDF，不保存返回密钥。
- `crypto.encrypt_entries` / `decrypt_entries`: JSON 序列化与 AES-GCM 认证加解密。
- `storage._associated_data`: 公共头部的规范化编码。
- `storage.initialize_vault` / `load_vault` / `save_vault`: 队友使用的公共接口。
- `storage._write_document`: 仅写密文、拒绝覆盖初始化目标、原子保存。

## References

- [Course requirements](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi API and profiles](https://argon2-cffi.readthedocs.io/en/stable/api.html)
- [cryptography AESGCM](https://cryptography.io/en/stable/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
