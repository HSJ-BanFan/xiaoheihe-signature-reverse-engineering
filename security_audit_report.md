# 小黑盒 (com.max.xiaoheihe) 客户端安全审计与 Native 签名算法逆向深度分析报告

**报告编号**：`SEC-2026-XHH-001`  
**审计目标**：小黑盒 Android 客户端 (`app-release.apk`)  
**包名**：`com.max.xiaoheihe`  
**样本 SHA-256**：`941d6365a12053ee711aa4548dbbb3f830d1beae29323df06e8fb571340b2fbe`  
**架构类型**：ARM64 (AArch64)  
**审计完成日期**：2026-09-29  
**验证状态**：**100% 全链路已验证（包含纯 PC 端脱机仿真与真实业务接口穿透）**

---

## 1. 任务背景与核心结论 (Executive Summary)

针对小黑盒 Android 客户端核心网络 API 请求防刷防篡改体系开展逆向工程分析。目标核心通信接口通过 18 项复杂设备参数及底层 Native 动态签名的**四元组绑定体系 (`_time`, `nonce`, `hkey`, `_rnd`)** 实现网关层严格防护。

### 核心技术结论
1. **`hkey` 算法完整数学解密**：
   - 输入数据：规范化路径 `Path/` 与十进制时间戳 `_time` 线性拼接（`Path + _time`）；
   - 哈希摘要：标准 80 轮 SHA-512，生成 64 字节（512 位）摘要；
   - 核心折叠：由底层 OLLVM 高度平坦化函数（`0x1D1964`）执行，本质是 **512 位输入映射到 32 位的 GF(2) 仿射线性变换**。通过基向量探测法完整还原了 $512 \times 32$ 维二元仿射矩阵与常数偏置 `BASE_BIAS = 0xb2fd95c6`，实现了 100% 比特精确、纳秒级纯代数 Python 算法复现。
2. **四元组严格绑定体系与 API 网关分界验证**：
   - API 网关要求四元组严格内聚绑定，单点伪造 `hkey` 无法穿透网关；
   - 负向实验：篡改 `hkey` 返回 `{"msg":"非法请求"}`（网关层拒绝）；
   - 签名放行实验：仅提交基础签名参数返回 `{"msg":"请求参数 \"offset\" 缺失"}`（网关 100% 放行，业务控制器提示缺少业务字段）；
   - 完整业务请求：携带分页参数请求 `/bbs/app/feeds/news` 成功返回 `HTTP 200 OK`，完整获取包含横幅与资讯流数据的真实业务 JSON。
3. **完全脱离手机/模拟器的 Unidbg 独立工程闭环**：
   - 识别并精准突破了 Native 库中针对环境探测的两处空指针自毁桩（`0x1C5A28`, `0x1C5AD4` 处的 `str w9, [xzr]`）与单线程调度下的多线程自旋等待死锁（`0x1C5C00`）；
   - 打包构建了单一独立的 fat JAR（`xiaoheihe-signer.jar`，40.94 MB），支持 CLI 命令行一键调用与本地 HTTP 微服务模式（默认端口 8088/8089），单次出签耗时 < 5ms。

---

## 2. 核心逆向技术分析与底层机制

### 2.1 签名四元组构成与协同机制

小黑盒 API 请求在 HTTP Query 中必须携带以下核心四元组：

```
                              【四元组协同流程】
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
      【1. 时间与会话句柄】                     【2. 动态防刷与哈希折叠】
    _time: Unix 时间戳字符串                  hkey: SHA512(Path+_time) GF(2)折叠
    nonce: 32位 Base62 槽位句柄              _rnd: 14: + getObjType(..., true)
```

1. **`_time`**：当前请求时间戳（秒级），在 `getIdxOffset`、`setBuf` 及 `Path` 拼接中全程参与；
2. **`nonce`**：长度严格为 32 字符的 Base62 字符串，由 Native 函数 `getIdxOffset`（`0x1CACD8`）在堆上动态分配 session slot 并返回句柄，用于服务端状态识别；
3. **`hkey`**：8 字符十六进制大写字符串，对 `Path + _time` 的 SHA-512 摘要进行 GF(2) 仿射投影得到 32 位整数；
4. **`_rnd`**：格式为 `14:<8位十六进制>`，由 Native 函数 `getObjType(ctx, nonce, true)`（`0x1D3F40`）结合设备模型、系统版本及包名计算生成。

### 2.2 hkey GF(2) 线性空间折叠矩阵推导

Native 库 `libglesv3_1.so` 中的 `0x1D1964` 内部包含超过 1200 条 OLLVM 控制流混淆块。通过对其代数性质进行抽象，证明其为 $GF(2)$ 空间上的仿射变换：

$$HKey = \left( \bigoplus_{i=0}^{511} \left( Digest[i] \cdot \mathbf{M}[i] \right) \right) \oplus \mathbf{Bias}$$

- **二元空间基底**：全零输入时输出常数基底 $\mathbf{Bias} = \text{0xb2fd95c6}$；
- **基向量提取**：通过分别将 512 位输入的每一个比特置 1 构造标准正交基，提取出完整的 512 个 32 位基向量并落盘于 `fold_matrix_basis.py`；
- **精度验证**：经过 10,000 次随机 SHA-512 摘要对照测试，纯代数 Python 算法与真机 ARM64 机器码计算结果的比特一致率为 **100.00%**。

---

## 3. 规避真机与模拟器：Unidbg 纯脱机仿真工程

为打破对真实物理手机或 Android 模拟器的依赖，满足工业级服务器端无头部署要求，本项目落地了基于 Unidbg 的 PC 端独立仿真方案。

### 3.1 突破的三大 Native 隐藏对抗机制
1. **全局单例容器（`0x218558`）自动引导**：
   - Native 层的 `getIdxOffset` 必须依赖 `0x218558` 指向的全局状态；
   - 通过在启动阶段预先触发 `setParseDepth(path, true)`（`0x1C5254`），引导 Native 底层完成内存空间的正确分配与结构初始化。
2. **空指针自毁桩击穿（Anti-Tamper Neutralization）**：
   - `setParseDepth` 内部检测 `/proc/self/cmdline` 与 `/proc/self/status`。若检测异常，会主动跳转至 `0x1C5A28` 与 `0x1C5AD4` 执行 `str w9, [xzr]`，故意制造空指针写入触发进程崩溃；
   - 在 Unidbg 中通过 `IOResolver` 虚拟化 `/proc` 输出，并通过 Backend Hook 在指令层直接截获这两个崩溃点并跳转至有效返回逻辑 `0x1C5AE4`。
3. **消除多线程原子自旋锁死锁（Pthread Spin-wait Elimination）**：
   - 初始化末尾会调用 `pthread_create`（`0x1C5BE8`）并在主线程通过 `0x1C5C00: ldar w8, [x8]` / `0x1C5C08: cmn w8, #1` 循环等待子线程标记变更；
   - 由于仿真器在单线程执行时无法调度后台线程，导致陷入死循环；通过将 `0x1C5C00` 的执行指令动态重定向至 `0x1C5C18`，瞬间击穿自旋锁。

---

## 4. 实网请求与正反向交叉验证证据

通过构建独立的客户端程序（`XiaoHeiHeClient.java`）发起真实网络请求，获得了完整的接口响应：

### 4.1 正反向对照实验表

| 实验组别 | 提交的签名与参数 | 服务端真实响应 | 阶段定性 |
| :--- | :--- | :--- | :--- |
| **负向对照组** | 篡改 `hkey` 或构造错误 `nonce` | `{"msg":"非法请求","status":"failed"}` | 网关层拦截（验签失败） |
| **放行验证组** | Unidbg 原生四元组，无分页参数 | `{"msg":"请求参数 \"offset\" 缺失","status":"failed"}` | **网关 100% 验签通过**，进入业务层报错 |
| **业务闭环组** | Unidbg 原生四元组 + 补齐 `offset=0&limit=20` | `{"msg":"","status":"ok","result":{"links":[...]}}` | **业务完全成功**，获取真实业务数据 |

### 4.2 真实抓取数据报文片段（截取）
```json
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{
  "msg": "",
  "result": {
    "links": [
      {
        "content_type": 23,
        "banners": [
          {
            "bottom_text": "",
            "title": "校友在玩PUBG？参与发帖赢道具",
            "img": "https://imgheybox1.max-c.com/oa/2026/09/22/c8d6fd9c73e4ed7ff25ecf37fd6f870c.png",
            "idea_id": "6ab25159b9e35851d7f9e37a"
          }
        ]
      }
    ],
    "feed_list": [ ... ]
  },
  "status": "ok"
}
```

---

## 5. 产物交付与微服务化集成

项目最终交付物已全部构建并归档在 `working/` 目录下：

### 5.1 交付工件清单
1. **独立可执行 Jar 包**：`cases/case-2026-apk01/working/xiaoheihe-signer.jar` (40.94 MB)
   - 内置完整 AArch64 仿真引擎与 JNI 桩环境，支持 Java 8+ 全平台环境；
   - 彻底脱离 Android OS、ADB、雷电模拟器或手机。
2. **纯算法推导复现脚本**：`cases/case-2026-apk01/working/fold_matrix_basis.py`
   - 包含 512 个仿射基向量与常数偏移量，支持纯 Python 快速计算 `hkey`。
3. **仿真源码工程**：`cases/case-2026-apk01/working/unidbg/unidbg-android/src/main/java/com/xiaoheihe/`
   - `XiaoHeiHeSignerRunner.java`：底层 JNI 虚拟化与防调自杀桩击穿实现；
   - `Main.java`：CLI 入口及内置 HTTP 微服务接口实现；
   - `XiaoHeiHeClient.java`：18 参数完整协议封装与实网测试客户端。

### 5.2 使用指南

#### 1. CLI 命令行直接生成
```bash
# 语法: java -jar xiaoheihe-signer.jar [path] [timestamp]
java -jar xiaoheihe-signer.jar "/bbs/app/feeds/news" 1790643100
```
**输出示例**：
```json
{"path":"/bbs/app/feeds/news/","_time":"1790643100","nonce":"3oCpwCioQCL3CXRW4SIKai3abwXba6Ci","hkey":"4C411BFF","_rnd":"14:559ED92E"}
```

#### 2. 本地 HTTP 微服务模式
```bash
# 启动本地签名服务，默认端口 8088
java -jar xiaoheihe-signer.jar --server 8088
```
**HTTP 接口调用**：
```bash
curl "http://127.0.0.1:8088/sign?path=/bbs/app/feeds/news"
```
**响应 JSON**：
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

## 6. 纵深防御与安全加固建议

针对本次逆向审计发现的技术脆弱性，建议小黑盒开发与安全团队实施以下加固：

1. **废弃弱随机性与可预测时间状态**：
   - `nonce` 槽位索引目前与单调递增时钟及静态种子强相关，建议接入基于硬件 Keystore / TEE 安全区域支持的动态非对称签名或服务端随机挑战机制；
2. **修补 Native 异常处理与单线程假定**：
   - 底层反篡改检测采用直接对 `0x0` 寻址写入的方式易被动态插桩与内存重映射轻易规避；应引入内核级 ptrace 双向心跳配合 libc 内联校验；
3. **加固 OLLVM 控制流混淆**：
   - 虽然函数控制流经过了平坦化混淆，但核心的散列压缩与仿射折叠逻辑在代数上仍呈严格的线性特性（GF(2) 线性空间不变性），极易被基底探测技术整体还原；建议在变换路径中引入非线性 S-Box 替换层与动态多项式密钥混淆。

---
*报告归档：Reverse Engineering Autonomous Workbench · 状态：全流程收口归档 (PASS)*
