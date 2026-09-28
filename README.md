# localsbom — 本地软件供应链 SBOM 生成与校验工具

一个**完全离线**的软件物料清单（SBOM）生成器、完整性校验器、许可证策略门禁和 SBOM
差异比较工具。支持本地的 **Python** 与 **Node.js** 工程，统一输出稳定的
[CycloneDX 1.5](https://cyclonedx.org/) JSON。

所有信息——依赖声明、lock 文件、包元数据、内容哈希、许可证策略、报告——**只来自
本地工程文件并保存在本地**。工具不访问 PyPI、npm registry、GitHub、任何漏洞 API 或
云服务。整个程序只使用 **Python 标准库**（要求 Python ≥ 3.11），无需安装任何第三方
依赖，因此连“安装依赖”这一步都不可能触发联网。

---

## 目录

- [支持的工程格式](#支持的工程格式)
- [快速开始](#快速开始)
- [命令](#命令)
- [SBOM 字段](#sbom-字段)
- [完整性校验规则](#完整性校验规则)
- [许可证策略规则](#许可证策略规则)
- [SBOM diff](#sbom-diff)
- [损坏输入与失败语义](#损坏输入与失败语义)
- [离线保证](#离线保证)
- [运行测试](#运行测试)
- [示例工程](#示例工程)
- [项目结构](#项目结构)

---

## 支持的工程格式

| 生态系统 | 声明文件（人写） | Lock 文件（机器生成） |
|---|---|---|
| Python | `pyproject.toml`（[PEP 621](https://peps.python.org/pep-0621/) 与 Poetry）、`requirements.in` | `uv.lock`、`Pipfile.lock`、带 `--hash` 的 `requirements.txt` |
| Node.js | `package.json`（`dependencies` / `devDependencies` / `optionalDependencies` / `peerDependencies`） | `package-lock.json`（lockfileVersion **1 / 2 / 3**）、经典 `yarn.lock`（**v1**） |

另外会扫描工程目录内**本地安装树**，提取本地可获得的元数据与哈希：

- Python：`.venv/`、`venv/`、`env/` 下的 `site-packages` / `dist-packages`，读取
  `.dist-info`（METADATA / PKG-INFO / RECORD，兼容 `.egg-info`）；
- Node.js：各级 `node_modules`（含 scoped 包与嵌套提升边界），读取已安装包的
  `package.json`。

版本约束按 PEP 440（`==`、`!=`、`>=`、`<=`、`~=`、复合约束）与 npm semver
（`^`、`~`、`1.x`、`*`、连字符区间）做本地机械化求值；PEP 508 环境标记
（`python_version`、`sys_platform` 等）按内置环境描述求值，无法解释的约束
**不会**被误判为不匹配，而是产生 `VERSION_UNCHECKED` 信息。

---

## 快速开始

无需安装、无需创建环境（标准库即可）；在仓库根目录执行：

```bash
python -m sbomtool generate examples/py-app --no-local
```

也可以只为本工具创建独立环境（同样不装任何包）：

```bash
conda create -y -n localsbom python=3.12
conda activate localsbom
python -m sbomtool --help
```

---

## 命令

### 1. `generate` — 生成 SBOM

```bash
python -m sbomtool generate <project_dir> [-o sbom.json] [--no-local]
```

- 自动发现 `project_dir` 下的声明与 lock 文件，合并声明、lock 与本地安装证据；
- 输出 CycloneDX 1.5 JSON。输出是**确定性**的：键排序固定、无时间戳、无随机序列号，
  相同输入重复生成得到逐字节相同的文件（便于 diff 与签名）；
- `--no-local`：不扫描 `site-packages` / `node_modules`，仅依据清单与 lock 文件。

### 2. `check` — 完整性校验 + 许可证策略

```bash
python -m sbomtool check <project_dir> [--policy policy.json] [--json] [-o report.json]
                                       [--no-local] [--allow-warnings]
```

输出人类可读报告（或 `--json` 机器报告），列出每一条问题的**严重级别、规则代码、
涉及组件与具体原因**。

### 3. `diff` — 比较两个 SBOM 版本

```bash
python -m sbomtool diff old_sbom.json new_sbom.json [--json]
```

按组件名（含生态系统）做集合比较，**输入顺序变化不会产生任何差异**。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 成功，且没有触发门禁的问题（diff 时表示无差异） |
| `1` | 报告已正常产出，但存在 error（或未加 `--allow-warnings` 时存在 warning）；diff 存在差异 |
| `2` | 输入文件或策略文件缺失/损坏/非法——**绝不输出看似成功的报告** |

---

## SBOM 字段

每个组件记录：

| 字段 | 说明 |
|---|---|
| 名称 / 版本 | 名称按生态系统规范化（PyPI 遵循 [PEP 503](https://peps.python.org/pep-0503/)：小写、`-_.` 归一；npm 小写并保留 `@scope`） |
| `purl` | `pkg:pypi/<name>@<version>` 或 `pkg:npm/...` |
| 来源类型 | `declaration`（仅声明）、`lock`（在 lock 中）、`local`（仅在本地安装树）、`lock+local`（lock 与本地均有证据） |
| 声明约束 | 声明文件里写下的原始约束，如 `>=2.31,<3`、`^1.2.0` |
| 依赖关系 | 传递依赖边（取自 lock 的 dependencies / requires-dist / requires / yarn 依赖块，经过环境标记过滤），输出到 CycloneDX `dependencies` |
| 内容哈希 | 本地可获得的所有哈希：lock 中的 `--hash` / uv wheel hash / Pipfile `hashes` / npm `integrity`（base64 解码为 hex）/ npm v1 `shasum`；本地 `RECORD` 哈希；已安装 `package.json` 的直接内容哈希。哈希标注来源：`lock`、`local-record`、`local-content` |
| 许可证 | SPDX 标识或许可证文本（uv / METADATA `License-Expression`、classifier 映射、package.json `license`） |
| scope | `required` / `optional`（可选依赖组、devDependencies 等） |
| evidence | 证明该组件存在的本地文件路径（写在组件 properties 中） |

CycloneDX 顶层还在 `metadata.properties` 中记录工程根目录与参与解析的 lock 文件。

---

## 完整性校验规则

| 代码 | 级别 | 触发条件 |
|---|---|---|
| `MISSING_PACKAGE` | error | 声明了依赖，但任何 lock 文件和本地安装树中都不存在 |
| `VERSION_MISMATCH` | error | lock 锁定版本不满足声明约束（如声明 `~1.2.0` 却锁定 `1.5.0`） |
| `VERSION_UNCHECKED` | info | 约束无法被可靠地机械化判定（不臆断为失败） |
| `DUP_VERSION` | error | 同名组件在多个 lock 中解析为**不同版本**（重复组件/版本不一致） |
| `BROKEN_DEPENDENCY` | error | 某组件引用的依赖没有任何组件提供（传递依赖缺失） |
| `NO_CONTENT_HASH` | warning | 被锁定的组件没有任何本地可获得的内容哈希 |
| `LOCK_MISS` | warning | 包只存在于本地安装树，未被任何 lock 文件记录（lock 与实际安装不符） |

示例：

```text
ERROR   MISSING_PACKAGE [npm:ghost]: declared dependency is absent from every lock file ...
ERROR   VERSION_MISMATCH [npm:@scope/pkg]: locked version 2.1.4 does not satisfy declared constraint '~2.1.0'
ERROR   DUP_VERSION [npm:a]: component resolved to multiple versions: ['1.0.0', '1.5.0']
ERROR   BROKEN_DEPENDENCY [npm:a@1.0.0]: dependency npm:vanished is referenced but no component provides it
WARNING LOCK_MISS [python:rogue]: package exists in the local install tree but is not recorded in any lock file
```

---

## 许可证策略规则

策略是本地 JSON 文件，例如 [`examples/policy.json`](examples/policy.json)：

```json
{
  "policy_version": 1,
  "action_on_unknown": "warn",
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0"],
  "deny":  ["GPL-3.0-only", "AGPL-3.0-only", "WTFPL"],
  "allow_unknown_components": []
}
```

- `allow`：允许的许可证；`deny`：拒绝的许可证（**拒绝优先**，多许可证组件中只要
  含一个被拒许可证即违规，但含一个被允许许可证即视为许可通过）；
- `action_on_unknown`：组件许可证不在策略表内或组件没有许可证时的动作——
  `allow` / `warn`（warning）/ `deny`（error）；
- `allow_unknown_components`：内部组件白名单，即使许可证未知也放行；
- 违规报告会给出**具体组件坐标**与命中的许可证，规则代码：
  `LICENSE_DENIED`、`LICENSE_UNKNOWN`、`LICENSE_UNKNOWN_DENIED`、
  `LICENSE_NOT_LISTED`、`LICENSE_NOT_LISTED_DENIED`。

**策略文件是严格校验的**：未知顶层键、错误类型、非法 action、非法许可证标识、
同一许可证同时出现在 allow/deny、不支持的 `policy_version`、文件损坏或根本不是
JSON 对象，都会以退出码 `2` 失败（`policy error: ...`），不会产生“看起来成功”的
报告。

---

## SBOM diff

`diff` 报告：新增组件（`added`）、删除组件（`removed`）、升级（`upgraded`）、
降级（`downgraded`）、**版本不变但内容哈希变化**（`version_same_hash_changed`，
用于发现同版本包被替换）、许可证变化、依赖边增删。

- 组件身份是 `生态系统:名称`，与文档内排列顺序无关；
- 所有集合在比较前排序；两份仅顺序不同的 SBOM 比较结果为空；
- 有差异时退出码为 `1`，便于 CI 门禁；损坏的 SBOM JSON 退出码为 `2`。

```bash
python -m sbomtool diff sbom-v1.json sbom-v2.json
# added     (1): npm:d
# removed   (1): npm:c
# upgraded  npm:b: 2.3.0 -> 2.4.0
# hash changed npm:a @ 1.2.0
```

---

## 损坏输入与失败语义

工具对输入采取**失败闭合（fail-closed）**态度，以下情况一律报错并以退出码 `2`
终止，不产出 SBOM 或成功报告：

- 声明/lock 文件不是合法 TOML / JSON / 语法无法解析；
- `package-lock.json` 的 `integrity` 不是合法 `算法-base64`；requirements 里
  `--hash` 非法；`Pipfile.lock` 条目不固定版本或哈希非法；
- lock 中的版本字段类型错误、包条目缺字段、lockfileVersion 不受支持（v4+）；
- 检测到 yarn berry（v2+）格式（仅支持经典 v1）；
- `requirements.txt` 作为 lock 时存在未固定（非 `==`）条目；
- 已安装的 `node_modules/*/package.json` 损坏；
- 策略文件任何模式的损坏/非法。

---

## 离线保证

- 代码仅 import Python 标准库（`tomllib`、`json`、`hashlib`、`email`、`csv`、
  `configparser`、`argparse`、`re` 等）；**不包含** `socket`、`urllib.request`、
  `http.client`、`subprocess` 等任何网络/进程能力，可直接审计：

  ```bash
  grep -rnE "socket|urllib\.request|http\.client|subprocess" sbomtool/
  ```

- `resolved` / registry URL 字段只作为字符串读取，从不发起请求；
- 不调用 pip/npm/yarn/uv，不解析任何远程索引；
- 测试全部在临时目录中构造夹具，不接触网络。

建议在防火墙或断网环境中运行以获得额外保障。

---

## 运行测试

测试基于标准库 `unittest`，**全部在终端执行**，不依赖浏览器或 GUI：

```bash
# 方式一：专用运行器（带汇总）
python tests/run_tests.py

# 方式二：标准 unittest 发现
python -m unittest discover -s tests -v
```

覆盖场景（86 个测试）：

- Python / Node 依赖解析、PEP 508 标记、传递关系与依赖图；
- npm lockfile v1/v2/v3、yarn v1、scoped 包、嵌套 node_modules、本地 venv；
- 缺失包、重复组件/多版本、版本不一致、lock 与声明漂移、悬空依赖；
- 哈希来源、同版本哈希变化、RECORD/integrity 解析；
- 许可证允许/拒绝/未知三态、内部组件豁免、违规组件定位；
- SBOM diff 的增删升降级、顺序无关性、字节级稳定输出；
- 损坏的声明/lock/策略/SBOM 输入必须失败；
- CLI 退出码与报告结构（通过子进程端到端测试）。

---

## 示例工程

- [`examples/py-app/`](examples/py-app)：Python 工程（`pyproject.toml` + `uv.lock`，
  含直接与传递依赖），预生成 [`sbom.json`](examples/py-app/sbom.json)；
- [`examples/node-app/`](examples/node-app)：Node.js 工程（`package.json` +
  `package-lock.json` v3，含 dev 依赖，其中 `left-pad` 为被策略拒绝的 WTFPL）；
- [`examples/policy.json`](examples/policy.json)：离线许可证策略。

试一次完整流程：

```bash
python -m sbomtool generate examples/node-app --no-local -o /tmp/node.json
python -m sbomtool check    examples/node-app --no-local --policy examples/policy.json ; echo "exit=$?"
python -m sbomtool diff     examples/py-app/sbom.json /tmp/node.json
```

---

## 项目结构

```
.
├── pyproject.toml              # 工具自身的（极简）项目元数据，零依赖
├── README.md
├── sbomtool/
│   ├── cli.py                  # generate / check / diff 命令与退出码
│   ├── analyzer.py             # 证据合并、统一清单、完整性校验
│   ├── models.py               # Component / SBOM / Finding 等数据模型
│   ├── parsers/
│   │   ├── python.py           # pyproject / requirements / uv / Pipfile
│   │   └── node.py             # package.json / package-lock v1-3 / yarn v1
│   ├── localmeta.py            # site-packages / node_modules 本地扫描
│   ├── cyclonedx.py            # 确定性 CycloneDX 1.5 JSON
│   ├── policy.py               # 离线许可证策略（严格校验）
│   ├── diff.py                 # 顺序无关的 SBOM 差异比较
│   ├── versions.py             # PEP 440 / npm semver 约束求值
│   ├── hashing.py              # 本地内容哈希与 lock 哈希解析
│   ├── naming.py               # PEP 503 / npm 名称规范化与 purl
│   ├── report.py               # 文本 / JSON 报告
│   └── errors.py               # InputError / PolicyError
├── examples/                   # 离线示例工程与策略
└── tests/                      # unittest 自动化测试 + run_tests.py
```
