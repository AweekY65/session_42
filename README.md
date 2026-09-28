# 本地离线软件供应链 SBOM 工具

一个**完全离线**的软件物料清单（SBOM）生成与校验工具。它解析本地 Python 与
Node.js 工程的依赖声明与 lock 文件，生成统一的组件清单（CycloneDX 1.5 JSON），
并支持依赖完整性校验、本地许可证策略检查和 SBOM 版本间 diff。

> **离线保证**：所有依赖清单、包元数据、哈希、策略和报告**只来自工程文件并保存在
> 本地**。工具代码仅使用 Python 标准库，**不会**访问 PyPI、npm、GitHub、漏洞 API
> 或任何外部服务（代码中不存在任何网络调用原语）。

---

## 目录

- [支持的工程格式](#支持的工程格式)
- [功能一览](#功能一览)
- [安装与运行](#安装与运行)
- [命令用法](#命令用法)
- [SBOM 字段说明](#sbom-字段说明)
- [许可证策略规则](#许可证策略规则)
- [完整性校验规则](#完整性校验规则)
- [SBOM diff](#sbom-diff)
- [损坏与非法输入的处理](#损坏与非法输入的处理)
- [测试](#测试)
- [示例工程](#示例工程)
- [项目结构](#项目结构)

---

## 支持的工程格式

| 生态 | 依赖声明文件 | lock 文件 |
|---|---|---|
| Python | `requirements*.txt`（含 `-r` 包含、`--hash`、直接 URL、`-e` 可编辑安装）、`pyproject.toml`（PEP 621 与 Poetry 两种写法）、`Pipfile` | `poetry.lock`、`Pipfile.lock`、全固定版本的 `requirements.txt`（自身即 lock） |
| Node.js | `package.json`（`dependencies` / `devDependencies` / `optionalDependencies` / `peerDependencies`） | `package-lock.json`（lockfileVersion **1 / 2 / 3**）、`yarn.lock`（classic / v1） |

一个目录可以同时包含 Python 与 Node.js 工程，两边的组件会合并进同一个 SBOM。
同一个生态下若同时存在两个 lock 文件（例如 `package-lock.json` 与 `yarn.lock`，
或 `poetry.lock` 与 `Pipfile.lock`），工具会拒绝在歧义下继续。

---

## 功能一览

1. **统一组件清单**：名称、版本、来源类型、许可证、内容哈希、依赖关系（含传递依赖）。
2. **稳定的 CycloneDX 1.5 JSON**：键排序、组件与依赖边排序、无时间戳/随机序列号，
   相同输入永远产生字节一致的输出。
3. **依赖完整性校验**：缺失包、重复组件（多版本共存）、声明版本与 lock 不一致、
   lock 文件缺失、哈希缺失、悬空依赖边。
4. **本地许可证策略**：允许列表 / 拒绝列表、未知许可证处理、SPDX `AND`/`OR`/`WITH`
   表达式、忽略名单，并输出具体违规组件。
5. **SBOM diff**：新增、删除、升级、降级、同版本哈希变化；**输入顺序变化不会产生
   无意义差异**。
6. **严格的输入校验**：任何损坏或非法的清单/lock/策略/SBOM 都会产生明确错误和非零
   退出码，绝不会输出看似成功的报告。

---

## 安装与运行

需要 Python 3.11+（标准库自带 `tomllib`）。**无需联网安装任何第三方包**。

```bash
# 方式一：直接在仓库根目录运行
python3 -m sbomtool --help

# 方式二：以可编辑模式安装（仍然不需要第三方依赖）
pip install -e .
sbomtool --help
```

如需独立 conda 环境（可选）：

```bash
conda create -y -n sbom python=3.11 pytest
conda activate sbom
python3 -m sbomtool --help
```

---

## 命令用法

### 1. 生成 SBOM

```bash
python3 -m sbomtool generate ./examples/node-project \
    --sbom out/sbom.json \
    --report out/report.json \
    --policy examples/policies/allowlist.json \
    --licenses examples/policies/licenses.json
```

- `--sbom`（必填）：CycloneDX JSON 输出路径。
- `--report`（可选）：完整性 + 许可证策略报告输出路径。
- `--policy`（可选）：本地许可证策略文件。
- `--licenses`（可选）：本地「包名 → 许可证」目录（为 lock 中没有许可证信息的包
  提供本地许可证数据）。
- `--name`（可选）：覆盖聚合工程名称。

退出码：`0` 全部通过；`1` 存在 error 级问题或策略违规；`2` 输入/配置损坏。

### 2. 校验工程（可对比既有 SBOM 是否漂移）

```bash
python3 -m sbomtool validate ./examples/node-project \
    --policy examples/policies/allowlist.json \
    --sbom out/sbom.json \
    --report out/report.json
```

`--sbom` 存在时，工具会从本地工程重新生成清单并与该文件逐组件对比，任何不一致都
报告为 `SBOM_DRIFT`。`validate` 必须提供 `--policy`。

### 3. 比较两个 SBOM

```bash
python3 -m sbomtool diff old-sbom.json new-sbom.json --report diff.json
```

没有差异退出码为 `0`，存在任何新增/删除/升级/降级/哈希变化时为 `1`，输入损坏
时为 `2`。

---

## SBOM 字段说明

输出为 CycloneDX 1.5 JSON（`bomFormat: "CycloneDX"`）。每个组件（library）记录：

| 字段 | 含义 |
|---|---|
| `name` / `version` | 包名（原始写法）与 lock 中解析出的具体版本 |
| `purl` | Package URL：`pkg:pypi/<名>@<版>` 或 `pkg:npm/<名>@<版>`（支持 `@scope/pkg`） |
| `bom-ref` | 稳定唯一标识，默认与 purl 一致；非 registry 来源带 `#source=<类型>` |
| `hashes` | 本地可得内容哈希：pip `--hash=sha256:…`、npm/yarn 的 `integrity`（自动从 base64 转为规范十六进制）、Pipfile.lock 的 `hashes`、本地路径依赖的目录/文件哈希 |
| `licenses` | lock 中携带的 SPDX 许可证（poetry.lock、package-lock、package.json 等） |
| `properties` | 结构化附加字段（见下） |
| 依赖边 | 顶层 `dependencies` 段记录 `ref → dependsOn[]`，包含传递依赖；聚合根挂各生态根，生态根挂直接依赖 |

`properties` 中的关键字段：

- `sbom:ecosystem`：`python` 或 `npm`
- `sbom:sourceType`：`registry` / `declared` / `url` / `file` / `vcs` / `workspace`
- `sbom:scope`：`required` / `optional`
- `sbom:sourceFile`：相对工程根的来源文件名
- `sbom:depSpec:<规范化包名>`：该组件对某依赖声明的原始版本约束

包名按生态规范化用于身份比较：Python 遵循 PEP 503（`-_.` 折叠为 `-` 并小写），
npm 保留 scope 并小写（`@Scope/Pkg` → `@scope/pkg`）。

---

## 许可证策略规则

策略为本地 JSON 文件（示例：`examples/policies/allowlist.json`）：

```json
{
  "version": 1,
  "policy": "allowlist",
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "deny": ["GPL-3.0-only", "WTFPL"],
  "onUnknown": "error",
  "ignore": ["some-internal-pkg"]
}
```

- `policy`：`allowlist`（默认，只允许 `allow` 中的许可证）或 `denylist`（除 `deny`
  外都允许）。
- **deny 永远优先于 allow**。
- `onUnknown`：组件没有任何许可证信息时的策略 —— `error`（默认，记错误）、
  `warn`（记警告）、`allow`（放行）。
- `ignore`：按规范化包名豁免（可写 `包名` 或 `python:包名` / `npm:包名` 限定生态）。
- 支持 SPDX 复合表达式：`MIT OR GPL-3.0-only`（任一分支允许即允许，所有分支都被拒
  才拒绝）、`MIT AND Apache-2.0`（每个分支都必须允许）、`X WITH Y`（按 `X` 判定）。
- 匹配大小写不敏感。

策略文件被严格校验：未知键、非法模式、非法 `onUnknown`、allowlist 但 `allow` 为空、
重复条目、错误的版本号、JSON 语法错误 —— 全部直接报错（退出码 2），**不会**产生
报告。

可选的许可证目录（`--licenses`）是本地 JSON，例如：

```json
{ "python": {"iniconfig": "MIT"}, "npm": {"some-pkg": "MIT"} }
```

---

## 完整性校验规则

报告 `integrityIssues` 中可能出现的问题码：

| 问题码 | 严重级别 | 含义 |
|---|---|---|
| `LOCK_MISSING` | error | 有依赖声明但没有任何 lock 文件 |
| `MISSING_PACKAGE` | error | 声明的直接依赖在 lock 中不存在（按 PEP 440 / semver 判定，marker 在当前环境为假的依赖跳过） |
| `VERSION_MISMATCH` | error | lock 解析版本不满足声明约束（Python 支持 PEP 508 及 Poetry `^`/`~` 转换；npm 支持 `^`/`~`/`x`/`||`/连字符范围/交集） |
| `DUPLICATE_COMPONENT` | error/warning | 同名包多版本共存（Python 为 error，npm 钻石依赖常见，记 warning）或同版本重复条目 |
| `DUPLICATE_DECLARATION` | warning | 同一包在清单中重复声明 |
| `UNRESOLVED_VERSION` | warning | 无 lock 时组件版本无法确定 |
| `MISSING_HASH` | warning | registry 组件在 lock 中没有内容哈希 |
| `BROKEN_DEPENDENCY_EDGE` | warning | 组件依赖了清单中不存在的包 |
| `SBOM_DRIFT` / `SBOM_CORRUPT` / `SBOM_MISSING` | error | 既有 SBOM 不可复现 / 已损坏 / 不可读 |

报告顶层 `status` 为 `pass` / `warn` / `fail`，并含各问题码计数。

---

## SBOM diff

`diff` 输出 JSON 报告：`added` / `removed` / `upgraded` / `downgraded` /
`changed`（同版本哈希变化）/ `unchanged`，以及 `summary` 计数。

- 组件身份为 `(生态, 规范化包名)`，不依赖输入数组顺序——所有比较均基于排序后的
  索引，**打乱两个 SBOM 中组件的顺序不会产生任何差异**。
- 升级/降级用与生态匹配的版本比较规则（PEP 440 风格 / semver），无法解析时退化为
  字符串比较。
- 版本相同但某算法哈希不同，记入 `changed`（`change: "hash"`）。

---

## 损坏与非法输入的处理

工具采用「快速失败、绝不伪成功」原则：

- 损坏的 JSON/TOML/YAML 式 lock、非法 hash/integrity、不支持的 lockfileVersion、
  两个 lock 同时存在、`-r` 递归包含 —— 立即报错，退出码 2，不写 SBOM。
- 损坏/非法策略或许可证目录 —— 退出码 2，不产生报告。
- diff 目标不是合法 CycloneDX JSON —— 退出码 2。
- 校验本身通过但存在 error 级问题或策略违规 —— 退出码 1（SBOM 仍写出作为证据）。

---

## 测试

全部测试直接在终端运行，不依赖浏览器或 GUI（pytest，纯进程内）：

```bash
# 运行全部 169 个自动化测试
python3 -m pytest tests/ -v

# 也可使用仓库内配置
python3 -m pytest
```

测试覆盖：

- Python / npm 各类声明与 lock 的**依赖解析**
- 多层级**传递关系**（poetry.lock、package-lock v1/v3、yarn.lock）
- **重复包**与多版本共存（npm 钻石依赖、重复声明）
- **哈希变化**（本地路径依赖内容篡改、lock integrity 解析、SBOM 同版本哈希 diff）
- **许可证规则**（allow/deny/unknown、SPDX AND/OR、忽略名单、损坏策略拒绝执行）
- **SBOM diff**（新增/删除/升级/降级/顺序无关/作用域包名）
- **损坏输入**（坏 JSON/TOML、非法 hash、非法策略、递归 include、双 lock、空目录）
- CLI 端到端退出码与文件产出

---

## 示例工程

- `examples/python-project/`：Poetry 工程 + `poetry.lock`（Flask 传递依赖链）。
- `examples/node-project/`：`package.json` + lockfileVersion 3（含故意使用拒绝许可证
  WTFPL 的 `left-pad`，用于演示策略违规）。
- `examples/policies/allowlist.json`、`examples/policies/licenses.json`。

快速演示：

```bash
python3 -m sbomtool generate examples/node-project \
    --sbom /tmp/npm.json --policy examples/policies/allowlist.json
# 退出码 1：left-pad 的 WTFPL 被拒绝
```

---

## 项目结构

```
sbomtool/
├── __main__.py          # python -m sbomtool 入口
├── cli.py               # generate / validate / diff 命令
├── model.py             # Component / ProjectScan 等数据模型、包名规范化
├── versions.py          # PEP 440 / semver 约束匹配（离线实现）
├── pep508.py            # PEP 508 需求与 marker 解析
├── hashing.py           # 本地文件/目录哈希、lock hash 归一化
├── integrity.py         # 缺失/重复/不一致/悬空边等完整性分析
├── policy.py            # 许可证策略加载、校验与求值
├── cyclonedx.py         # 稳定 CycloneDX 1.5 JSON 生成
├── diff.py              # 顺序无关的 SBOM 比较
├── report.py            # 报告汇总与确定性 JSON 序列化
└── parsers/
    ├── python_scan.py   # requirements / pyproject / poetry / Pipfile
    ├── npm_scan.py      # package.json / package-lock v1-3 / yarn.lock
    └── project.py       # 生态探测与编排
tests/                   # 全部自动化测试
examples/                # 可直接运行的离线示例
```
