# Fork 自有改动的上游覆盖状态调研

- 调研日期：2026-09-20
- 本地仓库：[`eicky/sublink-worker`](https://github.com/eicky/sublink-worker)
- 上游仓库：[`7Sageer/sublink-worker`](https://github.com/7Sageer/sublink-worker)
- 对比基线：上游 `v2.4.1`，commit [`1cde4a1ef2b03db84b2a04f8999c3344ce6b71dc`](https://github.com/7Sageer/sublink-worker/commit/1cde4a1ef2b03db84b2a04f8999c3344ce6b71dc)
- 固定的上游默认分支快照：`main` @ [`3361ad72630bbd328a0a01c49f553aaa985889c3`](https://github.com/7Sageer/sublink-worker/commit/3361ad72630bbd328a0a01c49f553aaa985889c3)，author time `2026-09-13T02:58:02Z`，committer time `2026-09-13T02:58:16Z`
- 上游最新正式 release：[`v2.4.2`](https://github.com/7Sageer/sublink-worker/releases/tag/v2.4.2)，发布于 `2026-04-27T03:34:15Z`，annotated tag 最终指向 commit [`e465a79db5fa1cf768153be4ce57f2a65cdc5921`](https://github.com/7Sageer/sublink-worker/commit/e465a79db5fa1cf768153be4ce57f2a65cdc5921)
- fork 本地同名 tag `v2.4.2` 指向 [`67112c6d7acfbbd7c0955aa0ae6c4c634bdb87ce`](https://github.com/eicky/sublink-worker/commit/67112c6d7acfbbd7c0955aa0ae6c4c634bdb87ce)；它与上游 `v2.4.2` 的提交、内容和发布日期均不同，不能把同名版本视为等价制品

## 结论

| 本地修复 | 上游 `main`（固定 SHA） | 最新正式 release `v2.4.2` | 结论摘要 |
|---|---|---|---|
| [`93aa272`](https://github.com/eicky/sublink-worker/commit/93aa27272a0b3330677d56fe2f808b3d49ca60d2) Trojan URL 解析 | **部分修复** | **未修复** | 四个可观察行为修复中，`main` 只修复了“Trojan 默认启用 TLS”；`peer` SNI、ALPN、空 transport 仍未修复。额外的错误二次解析/无效回退清理也未采用，但有效非空密码的行为原本已正确。`v2.4.2` 四项行为均未包含。 |
| [`67112c6`](https://github.com/eicky/sublink-worker/commit/67112c6d7acfbbd7c0955aa0ae6c4c634bdb87ce) 移除 ARM64 构建 | **未采用 AMD64-only workaround；双架构构建成功** | **未采用 AMD64-only workaround；双架构构建成功** | 上游继续通过 QEMU 构建 `linux/amd64,linux/arm64`。基线、正式 release 和当前 `main` 的官方任务均成功；当前日志直接显示 ARM64 的 `npm install`、构建和 manifest 推送完成。 |

简言之：原作者后来覆盖了 `93aa272` 四项行为中的一项；另外三项仍需保留。Docker 方面未采用 AMD64-only workaround，但当前官方 AMD64+ARM64 构建成功。其余三个自有提交属于 fork 配置、发布元数据和诊断可观测性，而不是上游待修复的同类产品缺陷。

## 调研范围与本地分叉

本地 `HEAD` 为 `e66ff3aa6bab53b5b8abbc771d66d646309ee4d9`。从共同基线 `1cde4a1` 到本地 `HEAD` 的已知专有提交依次是：

1. [`93aa27272a0b3330677d56fe2f808b3d49ca60d2`](https://github.com/eicky/sublink-worker/commit/93aa27272a0b3330677d56fe2f808b3d49ca60d2) — `fix: correct Trojan protocol URL parsing issues`
2. [`b61f0d43bdfb3a0b683919ec56b726e06074fda5`](https://github.com/eicky/sublink-worker/commit/b61f0d43bdfb3a0b683919ec56b726e06074fda5) — `chore: update docker image registry to ghcr.io/eicky`
3. [`b36456ba7837a0b621a9546f12c33487fa59f66d`](https://github.com/eicky/sublink-worker/commit/b36456ba7837a0b621a9546f12c33487fa59f66d) — `chore: release v2.4.2`
4. [`67112c6d7acfbbd7c0955aa0ae6c4c634bdb87ce`](https://github.com/eicky/sublink-worker/commit/67112c6d7acfbbd7c0955aa0ae6c4c634bdb87ce) — `fix: remove arm64 build due to QEMU emulation issues`
5. [`e66ff3aa6bab53b5b8abbc771d66d646309ee4d9`](https://github.com/eicky/sublink-worker/commit/e66ff3aa6bab53b5b8abbc771d66d646309ee4d9) — `chore: add [sublink-debug] logging across subscription pipeline`

下文详细核对两个包含行为差异的提交，并对另外三个 fork 自有提交作性质分类；文末另以附注记录已核实的继承 Base64 旧分支，不把它计入 fork `main` 的五个自有提交。

上游对象通过以下只读命令取得并固定：

```text
git fetch --no-tags https://github.com/7Sageer/sublink-worker.git main
```

结果为 `FETCH_HEAD=3361ad72630bbd328a0a01c49f553aaa985889c3`。调研期间没有添加 remote，也没有 checkout、merge 或 rebase。

## 一、`93aa272`：Trojan URL 解析

### 本地提交的四个行为修复与一项代码清理

本地提交的[完整补丁](https://github.com/eicky/sublink-worker/commit/93aa27272a0b3330677d56fe2f808b3d49ca60d2)做了五处改动，其中后四项是面向常规有效链接的可观察行为修复；第一项主要是移除错误、无效的代码路径：

1. 删除 `parseServerInfo(addressPart)` 这次错误的二次解析，并删除无效的 `parsedURL.username` 密码回退。
2. 仅在 `params.type` 明确存在且不是 `tcp` 时创建 `transport`，避免缺少 `type` 时生成空 transport 对象。
3. Trojan URL 未指定 `security` 时默认使用 `tls`，但仍尊重显式的 `security=none`。
4. SNI 选择顺序扩展为 `sni || peer || host`。
5. 把 URL 的逗号分隔 `alpn` 参数写入 `tls.alpn` 数组。

### 分项状态

| 修复点 | 上游 `main` | `v2.4.2` | 证据与实际行为 |
|---|---|---|---|
| 删除错误二次解析及无效密码回退 | **未采用该清理** | **未采用该清理** | 当前 `main` 仍执行 `parseServerInfo(addressPart)`，并使用 `decodeURIComponent(password) || parsedURL.username`：[parser L8-L18](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/trojanParser.js#L8-L18)。但 `parseServerInfo` 只返回 `{host, port}`，没有 `username`：[utils L255-L269](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L255-L269)。正常非空密码因 `||` 左侧命中而早已正确解码；只有非常规空密码会从 `undefined` 变为 `""`。因此它是应保留的代码清理，但没有证据表明正常链接另有尚未修复的密码解析故障。release 中是同一旧逻辑：[release parser L8-L16](https://github.com/7Sageer/sublink-worker/blob/e465a79db5fa1cf768153be4ce57f2a65cdc5921/src/parsers/protocols/trojanParser.js#L8-L16)。 |
| 缺少 `type` 时不创建 transport | **未修复** | **未修复** | 当前判断仍是 `params.type !== 'tcp'`：[parser L12](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/trojanParser.js#L12)，所以 `undefined !== 'tcp'` 成立；helper 随后返回属性均为 `undefined` 的对象：[utils L312-L320](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L312-L320)。最小复现得到 `transport: {}`；当前 [`SingboxConfigBuilder.convertProxy`](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/builders/SingboxConfigBuilder.js#L104-L178) 不删除空 transport，因此差异会进入最终生成配置。release 也是相同判断：[release parser L10](https://github.com/7Sageer/sublink-worker/blob/e465a79db5fa1cf768153be4ce57f2a65cdc5921/src/parsers/protocols/trojanParser.js#L10)。 |
| Trojan 默认启用 TLS | **已修复** | **未修复** | 当前 `main` 在未指定 `security` 时执行 `params.security = 'tls'`：[parser L9-L11](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/parsers/protocols/trojanParser.js#L9-L11)。首次上游修复是 [`973d1a1`](https://github.com/7Sageer/sublink-worker/commit/973d1a1d4d7b7ef5e01b4d6a01bc9b5ebe496623)，由 [PR #389](https://github.com/7Sageer/sublink-worker/pull/389) 于 `2026-05-22T08:38:56Z` 合入，针对 [issue #388](https://github.com/7Sageer/sublink-worker/issues/388)；随后 [`5ac75bc`](https://github.com/7Sageer/sublink-worker/commit/5ac75bca714faf6bf000c0b56934e812ba145579) 增加了回归测试。`v2.4.2` 发布在该提交之前，仍直接以原参数调用 `createTlsConfig`，无默认 TLS：[release parser L9](https://github.com/7Sageer/sublink-worker/blob/e465a79db5fa1cf768153be4ce57f2a65cdc5921/src/parsers/protocols/trojanParser.js#L9)。 |
| 支持 `peer` 作为 SNI 备选 | **未修复** | **未修复** | 当前 TLS helper 仍只有 `params.sni || params.host`：[utils L289-L300](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L289-L300)，没有 `params.peer`。`peer`-only 最小复现中 `tls.server_name` 缺失。release 同样如此：[release utils L289-L300](https://github.com/7Sageer/sublink-worker/blob/e465a79db5fa1cf768153be4ce57f2a65cdc5921/src/utils.js#L289-L300)。 |
| 把 URL `alpn` 写入 `tls.alpn` | **未修复** | **未修复** | 同一 TLS helper 没有读取 `params.alpn`：[utils L289-L310](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L289-L310)。`alpn=h2,http%2F1.1` 的最小复现中 `tls.alpn` 缺失。release 同样缺失。 |

因此，按常规有效链接的四个行为修复计，当前上游 `main` 为 **部分修复（1/4）**，最新正式 release 为 **未修复（0/4）**。错误二次解析/无效回退另列为尚未采用的代码清理，不计入四项行为覆盖率。

### 最小行为复现

用两版本真实 `parseTrojan` 与 `SingboxConfigBuilder.convertProxy` 运行以下完全虚构的链接并 JSON 序列化：

```text
trojan://pass@node.example:443?peer=sni.example&alpn=h2%2Chttp%2F1.1#test
```

- fork 输出：`tls.enabled=true`、`server_name="sni.example"`、`alpn=["h2","http/1.1"]`，且没有 `transport`。
- 固定的上游 `main` 输出：`tls.enabled=true`，但没有 `server_name` 和 `alpn`，并带有 `transport:{}`。
- 上游 `v2.4.2` 还会得到 `tls.enabled=false`。

一个样例即同时证明：上游 `main` 已覆盖默认 TLS，但 `peer` SNI、ALPN 和空 transport 三项仍需保留。

迁移时还需注意一个不属于 `93aa272` 修复范围的后续语义变化：上游在 [`a8b99af`](https://github.com/7Sageer/sublink-worker/commit/a8b99afd9ff6d4117b7b68db7e6b085f234c4b16) 删除了 Trojan 等 parser 的顶层 `network: 'tcp'`，并在 Sing-box builder 中防御性删除该字段，因为它会把出站限制为 TCP、禁用 UDP。故不能为了机械保留 fork 输出而把该旧字段重新带回新版。

## 二、`67112c6`：移除 ARM64 Docker 构建

### 本地提交的确切修复点

本地提交只改一行，把 Docker Buildx 的平台从：

```yaml
platforms: linux/amd64,linux/arm64
```

改为：

```yaml
platforms: linux/amd64
```

补丁说明这是对 ARM64 QEMU 下 `npm install` 出现 `Illegal instruction` 的临时规避：[本地 commit `67112c6`](https://github.com/eicky/sublink-worker/commit/67112c6d7acfbbd7c0955aa0ae6c4c634bdb87ce)。

### 上游未采用 AMD64-only workaround

- 当前 `main` 仍设置 QEMU，并构建 `linux/amd64,linux/arm64`：[workflow L26-L33](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/.github/workflows/docker-image.yml#L26-L33)、[L58-L67](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/.github/workflows/docker-image.yml#L58-L67)。
- `v2.4.2` 也仍构建相同两个平台：[release workflow L26-L33](https://github.com/7Sageer/sublink-worker/blob/e465a79db5fa1cf768153be4ce57f2a65cdc5921/.github/workflows/docker-image.yml#L26-L33)、[L58-L67](https://github.com/7Sageer/sublink-worker/blob/e465a79db5fa1cf768153be4ce57f2a65cdc5921/.github/workflows/docker-image.yml#L58-L67)。
- 多架构发布最初由 [`6f1e77b`](https://github.com/7Sageer/sublink-worker/commit/6f1e77b5bd6b9a753125e27f41d177c39f008ac8) 引入；截至固定 SHA，工作流历史中没有把平台缩减为 AMD64-only 的上游提交。

`main` 和上游 `v2.4.2` 都**未采用 AMD64-only workaround**；这不等同于构建故障仍存在。上游持续保留 ARM64，且没有对应的“改为单架构”提交。

### 但上游官方 ARM64 构建实际成功

上游一贯保留 ARM64，官方 Actions 记录没有呈现本地补丁描述的故障：

1. 共同基线 `v2.4.1` / `1cde4a1` 的 [Docker run #113](https://github.com/7Sageer/sublink-worker/actions/runs/24272711255) 成功；`Set up QEMU` 与 `Build and push` 均成功。
2. 最新 release commit `e465a79` 的 [Docker run #126](https://github.com/7Sageer/sublink-worker/actions/runs/24975278614) 成功；`Build and push` 于 `2026-04-27T03:36:45Z` 成功结束。
3. 当前固定 `main` SHA 的 [Docker run #183](https://github.com/7Sageer/sublink-worker/actions/runs/34734332763) 成功。其尚可读取的原始日志明确显示：
   - Buildx 参数为 `--platform linux/amd64,linux/arm64`；
   - `[linux/arm64 builder 4/7] RUN npm install` 在约 `83.8s` 后 `DONE`；
   - ARM64 的 `npm run build:node` 完成；
   - 两个平台的 manifest list 被导出并推送到 `main`、`latest` 和 `sha-3361ad7` 标签。

作为对照，fork 在本地 workaround 之前的手工 [run #1](https://github.com/eicky/sublink-worker/actions/runs/24848817465) 在 `Build and push` 阶段运行约六小时后被取消；应用 AMD64-only 补丁后的 [run #3](https://github.com/eicky/sublink-worker/actions/runs/24849299865) 成功。不过旧 run 的完整日志现已由 GitHub 返回 HTTP 410，无法从原始日志重新核验 commit message 所称的具体 `Illegal instruction` 行。

所以应区分两个问题：

- **方案选择**：上游未采用 AMD64-only workaround，继续发布双架构镜像。
- **当前行为**：上游 ARM64/QEMU 构建成功，故障在官方 CI 中不复现；没有证据表明当前上游需要这项 workaround。

## 三、其余三个 fork 自有提交

| commit | 性质 | 上游覆盖判断 |
|---|---|---|
| [`b61f0d4`](https://github.com/eicky/sublink-worker/commit/b61f0d43bdfb3a0b683919ec56b726e06074fda5) | 将 `docker-compose.yml` 的默认镜像从 `ghcr.io/7sageer/sublink-worker:latest` 改为 `ghcr.io/eicky/sublink-worker:latest` | fork 自有镜像地址配置，预期就不应由原作者“修复”或覆盖；是否保留取决于部署要跟随 fork 还是上游镜像。 |
| [`b36456b`](https://github.com/eicky/sublink-worker/commit/b36456ba7837a0b621a9546f12c33487fa59f66d) | 把 fork 版本标为 `2.4.2`，并将项目仓库及 release 检查 API 指向 `Eicky/sublink-worker` | fork 发布元数据与更新源，不是上游缺陷修复。它早于原作者同名 `v2.4.2`，且对应不同 commit；两者同名但不等价。 |
| [`e66ff3a`](https://github.com/eicky/sublink-worker/commit/e66ff3aa6bab53b5b8abbc771d66d646309ee4d9) | 在订阅抓取、解析及四个转换端点增加 `[sublink-debug]` 结构化日志 | 仅增强诊断可观测性；没有改变 User-Agent、重试、HTTP 403 处理或订阅抓取业务逻辑，不能把“增加日志”认定为订阅失败已经修复。 |

## 附：继承的旧 Base64 分支

远端仍有 `origin/claude/base64-to-subscription-011CULJBKw4S4vbfxzqFg5z1`，其 tip 为 [`3757599d`](https://github.com/eicky/sublink-worker/commit/3757599d0dfae58002de2d4dd2af435a297eaf0c)，包含 `/xray` 直接输入 Base64 时避免再次编码的实现。但该 commit 不在 fork `main`；它产生于 `2025-10-21`，而 `eicky/sublink-worker` 仓库创建于 `2026-04-23T17:09:37Z`。结合 [issue #232](https://github.com/7Sageer/sublink-worker/issues/232) 的报告者与时间，不能把这条继承分支归为 Eicky 的新增修复，也不计入 `1cde4a1..HEAD` 的五个专有提交。

上游已在不同实现的 [`65fe28d`](https://github.com/7Sageer/sublink-worker/commit/65fe28d8612b0c98757f5f3f3224500531788bb5)（`2025-10-21`）修复同类 Base64 重复编码问题；该提交是本地分叉基线 `1cde4a1` 的祖先。当前固定上游 SHA 的 `/xray` 路由仍先调用 `tryDecodeSubscriptionLines`，最后只编码一次：[createApp L287-L310](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/app/createApp.jsx#L287-L310)、[utils L95-L141](https://github.com/7Sageer/sublink-worker/blob/3361ad72630bbd328a0a01c49f553aaa985889c3/src/utils.js#L95-L141)。定向运行验证确认直接 Base64 单节点、多节点及 HTTP Base64 内容均保持单层编码，编码后的 path 也保留；测试使用 mock，未发出外部请求。

结论：这是“继承的旧分支所处理的问题已被上游以不同实现修复”，不是“旧分支 commit 已合入 main”。

## 行为修复与上游提交汇总

| fork 改动 | 上游状态 |
|---|---|
| Trojan 默认 TLS | [`973d1a1d4d7b7ef5e01b4d6a01bc9b5ebe496623`](https://github.com/7Sageer/sublink-worker/commit/973d1a1d4d7b7ef5e01b4d6a01bc9b5ebe496623)，2026-05-22，通过 [PR #389](https://github.com/7Sageer/sublink-worker/pull/389) |
| 删除错误的 `parseServerInfo(addressPart)` / 密码回退 | 截至 `3361ad7` 无 |
| 缺少 `type` 时不创建 transport | 截至 `3361ad7` 无 |
| `peer` 作为 SNI 备选 | 截至 `3361ad7` 无 |
| Trojan URL `alpn` 进入 `tls.alpn` | 截至 `3361ad7` 无 |
| Docker 改成 AMD64-only | 上游未采用该 workaround，并持续成功发布 AMD64+ARM64 |
| 附：继承旧分支涉及的 Xray Base64 重复编码 | 上游 [`65fe28d`](https://github.com/7Sageer/sublink-worker/commit/65fe28d8612b0c98757f5f3f3224500531788bb5) 已以不同实现修复，并已包含在分叉基线；不是 `3757599d` 合入 main |

## 验证限制

- 对 fork 的旧多架构 run，GitHub Actions 完整日志已过期并返回 HTTP 410；目前只能确认任务状态、时间、步骤状态以及本地 commit message，不能重新核验当时的具体异常栈。
- 环境中没有 Docker CLI，因此未额外从 GHCR 拉取 manifest；当前 `main` 的 Actions 原始日志已直接证明双平台构建和 manifest list 推送成功。
- Dockerfile 使用浮动的 `node:20-alpine`，而依赖锁文件后来也有变化；即使当前 ARM64 构建成功，也不能仅凭结果反推 fork 在 2026-04-23 出现异常的唯一根因。
- GitHub issue/PR 和提交历史检索未发现与该 QEMU `Illegal instruction` 直接对应的上游修复，但“未发现”不等于能证明从未有过外部或未公开讨论。
- 五个 fork `main` 自有提交均已分类；Base64 只作为不属于 fork `main` 自有改动的继承旧分支附注。
