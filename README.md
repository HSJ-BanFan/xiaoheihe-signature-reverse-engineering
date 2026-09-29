# 小黑盒 (XiaoHeiHe) API 签名逆向分析与纯脱机仿真技术报告

本项目为针对小黑盒 Android 客户端核心网络 API 签名体系（`hkey`、`nonce`、`_rnd`、`_time`）的逆向工程研究成果。记录了从初期控制流分析、密码学线性空间抽象，到最终利用 Unidbg 绕过多重底层对抗并实现纯 PC 端无模拟器脱机出签的全过程。

---

## 目录
- [一、 签名体系架构概述](#一-签名体系架构概述)
- [二、 逆向攻坚关键阶段回顾](#二-逆向攻坚关键阶段回顾)
  - [阶段 1：hkey 算法的 GF(2) 线性空间折叠与矩阵提取](#阶段-1hkey-算法的-gf2-线性空间折叠与矩阵提取)
  - [阶段 2：四元组与网关分界实验验证](#阶段-2四元组与网关分界实验验证)
  - [阶段 3：Unidbg 纯脱机仿真环境搭建](#阶段-3unidbg-纯脱机仿真环境搭建)
  - [阶段 4：突破三大底层隐藏对抗](#阶段-4突破三大底层隐藏对抗)
- [三、 交付产物与使用方式](#三-交付产物与使用方式)
  - [1. 纯代数 Python 复现脚本](#1-纯代数-python-复现脚本)
  - [2. 独立 Fat JAR（CLI 命令行与 HTTP 微服务）](#2-独立-fat-jarcli-命令行与-http-微服务)
- [四、 核心接口实测验收矩阵](#四-核心接口实测验收矩阵)
- [五、 纵深安全防御建议](#五-纵深安全防御建议)

---

## 一、 签名体系架构概述

小黑盒移动端与服务端交互时，API 网关通过 18 项复杂环境参数及 Native 层动态生成的**签名四元组**执行强制验签：

```
                    【小黑盒请求签名协同流程】
                               │
       ┌───────────────────────┴───────────────────────┐
       ▼                                               ▼
【基础环境与会话】                               【加密与哈希折叠】
• _time: 秒级时间戳                              • hkey: SHA512(Path+_time) GF(2)投影
• nonce: 32位 Base62 堆槽位句柄                  • _rnd: 14: + getObjType(..., true)
```

- **`_time`**：客户端时间戳；
- **`nonce`**：由 Native 函数 `getIdxOffset`（`0x1CACD8`）在内部堆上动态分配的 32 字符 Base62 句柄，代表一次会话上下文；
- **`hkey`**：8 字符十六进制大写，基于 `Path + _time` 的 512 位 SHA-512 摘要进行仿射折叠；
- **`_rnd`**：格式为 `14:<8位十六进制>`，由 Native 函数 `getObjType(ctx, nonce, true)` 结合设备模型与系统版本生成。

---

## 二、 逆向攻坚关键阶段回顾

### 阶段 1：hkey 算法的 GF(2) 线性空间折叠与矩阵提取

在 `libglesv3_1.so` 中，函数 `0x1D1964` 负责将 512 位的 SHA-512 摘要压缩为 32 位的整数。该函数受到 OLLVM 高度平坦化保护，包含 1,200+ 条混淆基本块。

通过差分代数探测，发现该变换在异或运算下具备完备的线性可加性：
$$F(A \oplus B) = F(A) \oplus F(B) \oplus \mathbf{Bias}$$

证明其本质是 **$\text{GF}(2)$ 二元线性空间上的 $512 \times 32$ 仿射矩阵投影**。
我们通过输入 512 组标准基向量，提取出完整的 512 个 32 位基底，并确定了全零输入下的偏移常量：
$$\mathbf{Bias} = \text{0xb2fd95c6}$$

**成果**：在 `fold_matrix_basis.py` 中实现了纯 Python 纯代数复现，单次计算仅需纳秒级，与真实 ARM64 原生机器码计算结果比特一致率达到 100%。

---

### 阶段 2：四元组与网关分界实验验证

在纯 Python 算法打通后，我们发现仅提交 `hkey` 仍会被服务端返回 `{"msg":"非法请求"}`。通过控制变量对照实验，厘清了服务端网关的架构分界：

| 实验组别 | 提交数据 | 服务端回显 | 定性 |
| :--- | :--- | :--- | :--- |
| **负向对照** | 篡改 `hkey` 或伪造 `nonce` | `{"msg":"非法请求"}` | **网关层拦截**（验签失败） |
| **网关放行** | 提交合法四元组，缺业务参数 | `{"msg":"请求参数 \"offset\" 缺失"}` | **网关 100% 放行**，业务控制器提示参数缺失 |
| **业务闭环** | 提交合法四元组 + 补齐业务分页 | `{"msg":"","status":"ok","result":{...}}` | **业务成功**，返回真实资讯流数据 |

该实验证明：**服务端在网关层对 `(nonce, _time, hkey, _rnd)` 执行全量校验**。`nonce` 经过了底层复杂的非线性置换，单靠 Python 截断难以完全覆盖，必须转向完整的脱机仿真。

---

### 阶段 3：Unidbg 纯脱机仿真环境搭建

为了彻底脱离 Android 手机与雷电模拟器，我们遵循工作台规范（`emulation-and-rpc.md`），基于 **Unidbg** 构建了纯 PC 端的脱机仿真方案。

- 修复 `unidbg/pom.xml`，升级 `maven-compiler-plugin 3.8.1` 并配置 `<release>8</release>`，确保在 JDK 21 环境下无警告编译通过；
- 构建 64 位仿真器实例，映射 `libglesv3_1.so` 并成功跑通 `JNI_OnLoad`。

---

### 阶段 4：突破三大底层隐藏对抗

在纯脱机执行 Native JNI 调用链时，我们识别并精准突破了小黑盒底层的三重对抗机制：

1. **单例容器单向依赖（`0x218558`）**：
   - `getIdxOffset` 依赖全局单例指针 `0x218558`；未初始化时寻址 `[x21, #0xa8]` 会直接触发 `UC_ERR_READ_UNMAPPED`（空指针崩溃）；
   - 解决方案：通过预先执行 `setParseDepth(path, true)`（`0x1C5254`），引导 Native 原生逻辑完成内存池分配。
2. **反篡改空指针自毁桩（Anti-Tamper Traps）**：
   - 在 `setParseDepth` 内部逆向发现反调试校验：检查 `/proc/self/cmdline` 是否匹配 `:pushservice` 以及 `/proc/self/status` 的 `open()` 状态；
   - 一旦触发异常，代码直接跳转到 `0x1C5A28` 与 `0x1C5AD4` 执行 `str w9, [xzr]`（故意制造空指针写入使进程崩溃）；
   - 解决方案：使用 `IOResolver` 虚拟化 `/proc` 文件系统，并利用 Unidbg 的 Backend Hook 将两处崩溃点直接重定向至有效出口 `0x1C5AE4`。
3. **单线程仿真下的多线程自旋锁死锁（Spin-lock Deadlock）**：
   - 代码末尾调用 `pthread_create`（`0x1C5BE8`）并在主线程通过 `0x1C5C00: ldar w8, [x8]` / `0x1C5C08: cmn w8, #1` 循环等待子线程标记变更；
   - 在单线程仿真调度下，子线程无法获得时间片，主线程陷入无限自旋死循环；
   - 解决方案：在 `0x1C5C00` 安装 Hook，强制将 PC 寄存器修改为 `0x1C5C18` 跳过自旋等待。
4. **ContextWrapper JNI 反射补全**：
   - 底层通过 `FindClass("android/content/ContextWrapper")` 反射调用 `getSharedPreferences("debug_info_config", MODE_PRIVATE)`；
   - 补全 `ContextWrapper` 虚拟桩及 `MODE_PRIVATE = 0` 常量，成功使 `getObjType` 吐出合法 `hkey` 与 `_rnd`。

---

## 三、 交付产物与使用方式

### 1. 纯代数 Python 复现脚本 (`fold_matrix_basis.py`)
无需任何外部库依赖即可计算 `hkey`：
```python
from fold_matrix_basis import fold_sha512_digest
import hashlib

data = b"/bbs/app/feeds/news/1790643100"
digest = hashlib.sha512(data).digest()
hkey = fold_sha512_digest(digest)
print(f"Hkey: {hkey:08X}")
```

### 2. 独立 Fat JAR (`xiaoheihe-signer.jar`，40.94 MB)
由 `maven-shade-plugin` 将全套 AArch64 仿真引擎与 Native SO 依赖打包为单体 Jar。

#### 命令行直接生成 (CLI Mode)
```bash
# 语法: java -jar xiaoheihe-signer.jar [path] [timestamp]
java -jar xiaoheihe-signer.jar "/bbs/app/feeds/news" 1790643100
```
**输出**：
```json
{"path":"/bbs/app/feeds/news/","_time":"1790643100","nonce":"3oCpwCioQCL3CXRW4SIKai3abwXba6Ci","hkey":"4C411BFF","_rnd":"14:559ED92E"}
```

#### 本地 HTTP 微服务 (Microservice Mode)
```bash
# 启动微服务（默认端口 8088）
java -jar xiaoheihe-signer.jar --server 8088
```
**HTTP 接口调用**：
```bash
curl "http://127.0.0.1:8088/sign?path=/bbs/app/feeds/news"
```
**返回 JSON**：
```json
{
  "code": 0,
  "data": {
    "path": "/bbs/app/feeds/news/",
    "_time": "1790643778",
    "nonce": "PKiqDL3bYWIJ5cbba4bxcLPwLawdPYqv",
    "hkey": "632FABFF",
    "_rnd": "14:72CF66E7"
  }
}
```

---

## 四、 核心接口实测验收矩阵

基于签名微服务，对小黑盒社区板块（`/bbs/app/` 系列）进行实测验收：

| 业务名称 | 路由路径 | 响应状态 | 验签判定 | 业务数据回显详情 |
| :--- | :--- | :---: | :---: | :--- |
| **综合资讯信息流** | `/bbs/app/feeds/news` | **200 OK** | **PASS** | 完整返回 22 组横幅与资讯流列表 |
| **主推荐个性化流** | `/bbs/app/feeds` | **200 OK** | **PASS** | 传递 `pull=1`，返回 125 KB 推荐文章流 |
| **特定话题信息流** | `/bbs/app/topic/feeds` | **200 OK** | **PASS** | 传递 `topic_id=1`，返回话题关联讨论 |
| **全站热搜词榜** | `/bbs/app/api/search/hot_words` | **200 OK** | **PASS** | 返回当前全站 Top 10 热搜关键词 |
| **搜索欢迎与发现** | `/bbs/app/api/search/welcome_page/v2` | **200 OK** | **PASS** | 返回搜索发现模块与推荐游戏标签 |
| **24h 热点新闻榜** | `/bbs/app/hot_news/main_list` | **200 OK** | **PASS** | 返回 24 小时内的热点快讯列表 |
| **社区活动排行榜** | `/bbs/app/hashtag/ranking` | **200 OK** | **PASS** | 返回热门活动排行榜明细 |
| **用户动态发表流** | `/bbs/app/profile/user/link/list` | **200 OK** | **PASS** | 传递 `userid`，返回用户个人主页动态 |
| **用户粉丝画像关系**| `/bbs/app/profile/follower/list` | **200 OK** | **PASS** | 传递 `userid`，返回粉丝用户列表 |
| **全站话题分类总览**| `/bbs/app/topic/categories` | **200 OK** | **PASS** | 返回 34.5 KB 全量核心话题分类树 |
| **二级子话题分类** | `/bbs/app/topic/sub/categories/v2` | **200 OK** | **PASS** | 传递 `category_id=1`，返回二级子话题 |

---

## 五、 纵深安全防御建议

1. **阻断客户端单方决策，引入非对称挑战机制**：
   - 现行机制依赖客户端本地单方生成的时钟与 `nonce` 槽位，易被脱机模拟；
   - 建议在敏感数据接口前增加一次由服务端签发的具有生命周期（TTL 60s）的一次性随机 Challenge Token。
2. **加固底层防调试与异常处理**：
   - 废除向 `0x0` 写入数据触发崩溃的简单自毁逻辑；建议改用内核级 ptrace 互斥监听与代码段自校验。
3. **消除散列折叠的线性特征**：
   - 核心折叠函数虽然有 OLLVM 平坦化混淆，但在代数结构上呈现纯粹的 $\text{GF}(2)$ 线性空间不变性；
   - 建议在折叠路径中引入非线性 S-Box 替换网络或引入动态密钥参与的多项式置换，破坏矩阵可叠加性。

---
*报告归档：Reverse Engineering Autonomous Workbench*
