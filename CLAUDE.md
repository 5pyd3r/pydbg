# CLAUDE.md

## 分支与协作规则

- **永远不在 master 分支上 commit。** 所有改动必须通过 feature 分支 + PR。
- Feature 分支命名：`feat/<描述>`、`fix/<描述>`、`refactor/<描述>`
- AI 绝不 merge PR，只有人能 merge。
- Merge 后删除 feature 分支：`git branch -d feat/xxx && git push origin --delete feat/xxx`
- **使用 git worktree 创建隔离工作目录。** 在新分支上工作前，通过 `git worktree add ../d3d_video-<branch> <branch>` 创建隔离目录，避免污染主工作区。完成后提交并推送至 GitHub。

## CI 失败处理

编译/测试失败时，按分类处理：
1. **编译错误** — 自动获取 CI 日志（`gh run view <id> --log-failed`），分析原因，修复后重新推送。最多重试 3 次。超过 3 次 → 微信通知用户决策。
2. **测试失败** — 尝试修复 1 次。失败 → 微信通知用户。确认是环境问题可 GTEST_SKIP 并计入遗留。
3. **链接/未知错误** — 即时微信通知用户，不自动处理。

## 决策分级

### 自主决策（不通知用户）
- 命名、实现细节、编译错误修复、测试编写、死代码删除、include 清理

### 自主决策 + PR 中记录
- 新增工具函数、代码重构（不改外部行为）、新测试、依赖小版本更新

### 必须微信通知用户
- 架构变更、新依赖引入/删除、API 破坏性变更、CI 不可自动修复、遗留问题、spec 确认

## PR 规范

用户想创建 PR 时自动生成：
- 标题：`feat/fix/refactor: 简述`
- 描述：改动摘要（3-5点）、文件列表、CI 链接、自主决策记录、遗留问题
不使用gh命令创建PR

## 微信通知

- 通过 wechat skill 的 socket_client.py 发送消息
- 通知类（不等待回复）：CI 状态、PR 创建、分支操作
- 决策类（等待回复）：架构选择、CI 不可修复、新依赖、spec 确认
- 用户 merge 后不重复通知


