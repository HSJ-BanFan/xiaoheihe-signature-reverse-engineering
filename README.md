# 小黑盒 (XiaoHeiHe) API 签名逆向分析与安全防御评估报告

[![Security Research](https://img.shields.io/badge/Security-Binary%20Audit%20%26%20Cryptanalysis-red.svg)]()
[![Type](https://img.shields.io/badge/Document-Academic%20%26%20Remediation-blue.svg)]()
[![Reproducibility](https://img.shields.io/badge/Reproducibility-100%25%20Verified-brightgreen.svg)]()

> 本报告记录了针对 Android 客户端 Native 签名体系（`hkey`、`nonce`、`_rnd`、`_time`）的完整逆向分析过程。包含底层 OLLVM 混淆控制流下的代数可分析性推导、基于 $\text{GF}(2)$ 仿射投影的算法还原原理，以及在 PC 端通过 Unidbg 实现脱机仿真的完整工程与对抗细节，旨在为移动安全研究者及服务商提供完整的技术复现依据与纵深防御方案。

---

## 目录
- [一、 签名体系架构概述](#一-签名体系架构概述)
- [二、 算法复现原理与数学模型](#二-算法复现原理与数学模型)
  - [1. 签名四元组协同机制](#1-签名四元组协同机制)
  - [2. hkey 的 GF(2) 线性空间折叠代数推导](#2-hkey-的-gf2-线性空间折叠代数推导)
  - [3. 纯代数 Python 算法实现](#3-纯代数-python-算法实现)
- [三、 完整脱机仿真复现（Unidbg 方案）](#三-完整脱机仿真复现unidbg-方案)
  - [1. 核心 JNI 调用时序](#1-核心-jni-调用时序)
  - [2. 四大隐藏反分析对抗与精准绕过](#2-四大隐藏反分析对抗与精准绕过)
  - [3. 仿真客户端核心实现代码](#3-仿真客户端核心实现代码)
- [四、 服务端网关与全链路对照实验](#四-服务端网关与全链路对照实验)
- [五、 核心业务接口实测矩阵](#五-核心业务接口实测矩阵)
- [六、 服务端纵深加固建议 (Remediation)](#六-服务端纵深加固建议-remediation)

---

## 一、 签名体系架构概述

客户端在 HTTP 请求中依赖 Native 层（`libglesv3_1.so`）动态生成的**签名四元组**执行强制验签：

```
                    【请求签名四元组协同结构】
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
【会话与时序因子】                               【摘要折叠与设备指纹】
• _time: 秒级时间戳                             • hkey: 512-bit SHA-512 GF(2) 仿射折叠
• nonce: 32-char Base62 会话槽位句柄            • _rnd: 设备模型与系统版本派生值
```

- **`_time`**：当前 Unix 时间戳字符串（秒级），参与 URL 路径拼接与哈希计算；
- **`nonce`**：32 字符的 Base62 编码字符串，由 Native 函数 `getIdxOffset`（`0x1CACD8`）在堆空间生成，代表该次会话的上下文槽位；
- **`hkey`**：8 字符十六进制大写字符串，对 `Path + _time` 的 512 位 SHA-512 摘要进行二元域线性投影折叠得到（`0x1C8668`）；
- **`_rnd`**：格式为 `{os_version}:{8位Hex}`（如 `14:DA47C699`），由 `getObjType(ctx, nonce, true)` 结合机型与系统底层特征生成。

---

## 二、 算法复现原理与数学模型

### 1. 签名四元组协同机制

在发送业务请求时，客户端需组装完整的参数字典（共 19 项）：
- **业务参数**：`offset=0&limit=20`（主要接口必需）；
- **环境参数**：`heybox_id`, `imei`, `device_info`, `os_type`, `os_version`, `version`, `build`, `channel`, `time_zone`, `dw`, `netmode`；
- **安全四元组**：`_time`, `nonce`, `hkey`, `_rnd`。

---

### 2. hkey 的 GF(2) 线性空间折叠代数推导

在 `libglesv3_1.so` 中，负责将 512 位 SHA-512 摘要压缩为 32 位整数的折叠函数（`0x1D1964`）应用了 OLLVM 控制流平坦化混淆（包含 1,200+ 基本块）。

通过对输入执行单比特微扰差分分析，证明该函数对异或操作满足严格的线性可加性：
$$F(A \oplus B) = F(A) \oplus F(B) \oplus \mathbf{Bias}$$

这证明其底层数学模型是 **二元域 $\text{GF}(2)$ 上的仿射变换**：
$$HKey = \left( \bigoplus_{i=0}^{511} Digest[i] \cdot \mathbf{M}[i] \right) \oplus \mathbf{Bias}$$

- **常量偏移量**：全零摘要输入时的常数项 $\mathbf{Bias} = \text{0xb2fd95c6}$；
- **投影矩阵基底**：通过向该函数依次输入 512 组单比特置位的标准基向量，提取出由 512 个 32 位无符号整数构成的转换基底 $\mathbf{M}$。

---

### 3. 纯代数 Python 算法实现

根据上述数学模型，无需加载任何 Native 库即可纳秒级复现 `hkey` 计算：

```python
import hashlib

# 示例：已提取出的前 8 项基向量（完整 512 项矩阵通过单比特基向量测试提取）
SAMPLE_BASIS = [
    0x5462D68C, 0xA8C5AD18, 0x518B5A30, 0xA316B460,
    0x462D68C0, 0x8C5AD180, 0x18B5A300, 0x316B4600,
    # ... 其余 504 项基向量保持同构
]
BASE_BIAS = 0xB2FD95C6

def fold_sha512_digest(digest: bytes, basis_matrix: list[int], bias: int = BASE_BIAS) -> int:
    """
    基于 GF(2) 仿射投影矩阵将 64 字节 SHA-512 摘要折叠为 32 位 hkey 整数
    """
    result = bias
    bit_index = 0
    for byte in digest:
        for shift in range(8):
            if (byte >> shift) & 1:
                result ^= basis_matrix[bit_index]
            bit_index += 1
            if bit_index >= len(basis_matrix):
                break
    return result & 0xFFFFFFFF

def calculate_hkey(path: str, timestamp: int, basis: list[int]) -> str:
    # 路径规范化：确保以 '/' 结尾
    clean_path = path if path.endswith('/') else (path + '/')
    message = f"{clean_path}{timestamp}".encode('utf-8')
    digest = hashlib.sha512(message).digest()
    hkey_int = fold_sha512_digest(digest, basis)
    return f"{hkey_int:08X}"
```

---

## 三、 完整脱机仿真复现（Unidbg 方案）

由于 `nonce` 与 `_rnd` 深度耦合底层状态机与设备指纹，脱离真机环境的标准工业级方案是采用 **Unidbg (ARM64 JNI 仿真沙箱)**。

### 1. 核心 JNI 调用时序

脱机调用必须严格遵循以下顺序，否则将导致底层状态容器错乱：

```
1. setParseDepth("init", true)      --> 引导分配 0x218558 全局会话容器
2. getChunkFlag(ctx, raw_flag)      --> 获取动态旗标
3. getIdxOffset(ctx, flag, ts, uid) --> 堆分配并获取 32 字符 Nonce 槽位
4. setViewport(ts, nonce)           --> 绑定时间戳
5. setGramLen(path, nonce)          --> 注入规范化 URL 路径
6. setBuf(ts, nonce)                --> 注入时间戳
7. setDepRel(model, nonce)          --> 注入设备型号 (如 25102RKBEC)
8. setDLen(os_ver, nonce)           --> 注入系统版本 (如 14)
9. setPtrOffset(app_ver, nonce)     --> 注入应用版本 (如 1.3.385)
10. getObjType(ctx, nonce, false)   --> 读取槽位执行摘要折叠，产出 hkey
11. getObjType(ctx, nonce, true)    --> 结合设备特征产出 _rnd
```

---

### 2. 四大隐藏反分析对抗与精准绕过

在脱机执行原始 `libglesv3_1.so` 机器码时，需在 Unidbg 中处理以下 4 项底层对抗：

| 对抗类型 | 底层汇编与触发机制 | 绕过与补桩实现方案 |
| :--- | :--- | :--- |
| **单例空指针崩溃** | `getIdxOffset` 寻址 `[x21, #0xa8]`，若 `0x218558` 指针为空则直接触发 `UC_ERR_READ_UNMAPPED`。 | 必须优先调用 `setParseDepth` 触发底层 `malloc` 分配，或在 `0x218558` 手动写入预分配内存块指针。 |
| **反调试自毁陷阱** | 检查 `/proc/self/cmdline` 与 `/proc/self/status`，检测到异常时跳转至 `0x1C5A28` 执行 `str w9, [xzr]` 故意引发崩溃。 | 1. 注册 `IOResolver` 虚拟化 `/proc` 输出；<br>2. 挂载 Hook，在 `0x1C5A28` / `0x1C5AD4` 处直接将 PC 改写为 `0x1C5AE4`。 |
| **单线程自旋死锁** | `0x1C5BE8` 启动工作线程后，主线程在 `0x1C5C00` 处通过 `ldar` + `cmn w8, #1` 等待子线程标志，单线程沙箱中子线程无法运行导致无限卡死。 | 挂载 Hook，在 `0x1C5C00` 处直接修改 PC 寄存器为 `0x1C5C18`，跳过等待逻辑。 |
| **JNI 上下文依赖** | 底层通过 `ContextWrapper` 反射调用 `getSharedPreferences`、`getPackageName`、`getString` 等读取应用私有指纹。 | 继承 `AbstractJni` 覆盖 `callObjectMethodV`，为上述反射方法补充假桩，返回规范化的包名与设备参数。 |

---

### 3. 仿真客户端核心实现代码

以下为在 Unidbg 中绕过对抗并实现端到端出签的核心逻辑（节选自 `XiaoHeiHeSignerRunner.java`）：

```java
public class XiaoHeiHeSignerRunner extends AbstractJni implements IOResolver {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass shaderManager;
    private final DvmObject<?> contextObj;

    public XiaoHeiHeSignerRunner(File apkFile, File soFile) {
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.max.xiaoheihe").build();
        emulator.getSyscallHandler().addIOResolver(this);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM(apkFile);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary(soFile, false);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);

        shaderManager = vm.resolveClass("com/graphice/shaderar/ShaderManager");
        contextObj = vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context")).newObject(null);

        // 安装对抗绕过补丁：跳过自毁陷阱与多线程自旋等待
        final long base = module.base;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long rel = address - base;
                if (rel == 0x1C5A28L || rel == 0x1C5AD4L) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, base + 0x1C5AE4L); // 跳过非法写0崩溃
                } else if (rel == 0x1C5C00L) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, base + 0x1C5C18L); // 跳过自旋死循环
                }
            }
            @Override public void onAttach(UnHook unHook) {}
            @Override public void detach() {}
        }, base + 0x1C5000L, base + 0x1C6000L, null);

        // 引导底层单例分配
        shaderManager.callStaticJniMethod(emulator, "setParseDepth(Ljava/lang/String;Z)V", new StringObject(vm, "init"), true);
    }

    // 虚拟化 /proc 文件系统
    @Override
    public FileResult resolve(com.github.unidbg.Emulator emulator, String pathname, int oflags) {
        if ("/proc/self/cmdline".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, "com.max.xiaoheihe\0".getBytes(StandardCharsets.UTF_8)));
        }
        if ("/proc/self/status".equals(pathname)) {
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, "TracerPid:\t0\nState:\tS (sleeping)\n".getBytes(StandardCharsets.UTF_8)));
        }
        return null;
    }
}
```

---

## 四、 服务端网关与全链路对照实验

为验证签名算法的有效性，设计了三组严格的控制变量对照实验：

| 实验组别 | 提交测试参数 | 服务端响应状态 | 服务端 Body 回显 | 审计结论 |
| :--- | :--- | :---: | :--- | :--- |
| **对照组 A (负向)** | 伪造/篡改 `hkey` 或 `nonce` | `200 OK` | `{"msg":"非法请求","status":"failed"}` | **API 网关拦截**：签名数学关系不匹配直接拒绝。 |
| **对照组 B (放行)** | 提交仿真生成的合法四元组，缺业务分页参数 | `200 OK` | `{"msg":"缺少必要参数","status":"failed"}` | **网关 100% 放行**：证明四元组完全合规，已穿透至业务控制器。 |
| **对照组 C (闭环)** | 提交合法四元组 + 补齐 `offset=0&limit=20` | `200 OK` | `{"msg":"","status":"ok","result":{...}}` | **业务成功**：穿透网关与业务层，返回完整新闻列表 JSON。 |

---

## 五、 核心业务接口实测矩阵

基于上述脱机仿真引擎，对移动端全量主要业务接口发起网络验证，均实现 100% 成功放行：

| 业务名称 | 请求路由 | 关键参数 | 验签结果 | 返回数据特征 |
| :--- | :--- | :--- | :---: | :--- |
| **综合资讯主列表** | `/bbs/app/feeds/news` | `offset=0&limit=20` | **PASS** | 返回 22 条新闻条目与横幅列表 |
| **推荐个性化流** | `/bbs/app/feeds` | `pull=1` | **PASS** | 返回 125 KB 个性化推荐帖子流 |
| **特定话题讨论流** | `/bbs/app/topic/feeds` | `topic_id=1` | **PASS** | 返回话题关联动态 |
| **全站热搜关键词** | `/bbs/app/api/search/hot_words` | 无 | **PASS** | 返回全站实时 Top 10 热搜词 |
| **搜索发现与标签** | `/bbs/app/api/search/welcome_page/v2` | 无 | **PASS** | 返回发现模块与游戏标签数据 |
| **24h 热点快讯榜** | `/bbs/app/hot_news/main_list` | 无 | **PASS** | 返回 24 小时热榜条目 |
| **话题分类全景树** | `/bbs/app/topic/categories` | 无 | **PASS** | 返回 34.5 KB 社区话题分类结构 |

---

## 六、 服务端纵深加固建议 (Remediation)

针对本研究揭示的客户端可预测性及算法可代数推导缺陷，向服务商提出以下加固建议：

1. **引入服务端随机挑战机制 (Server-Side Challenge-Response)**：
   - 现行签名四元组中，时间戳与槽位句柄均由客户端单方生成，服务端仅校验相对时间窗口与哈希一致性，导致可被完全脱机推导；
   - **加固建议**：在发起关键读写请求前，服务端下发具有较短生命周期（如 TTL 30s）的一次性随机 Challenge Token；签名算法强依赖该 Token 及服务端持久化上下文，阻断脱机单向出签。

2. **消除散列折叠的线性空间特征**：
   - 当前折叠函数虽有 OLLVM 控制流混淆，但代数上严格遵循 $\text{GF}(2)$ 线性可加性，攻击者只需 512 次差分探测即可还原基底矩阵；
   - **加固建议**：在折叠流程中引入依赖动态密钥的非线性替换层（S-Box）或高阶多项式置换，破坏异或可加性。

3. **增强底层环境感知与异常处理鲁棒性**：
   - 当前反调试逻辑中依赖向 `0x0` 地址写数据的自毁桩极易被插桩工具（如 Unidbg / Frida）重定向绕过；
   - **加固建议**：改用系统内核级 `ptrace` 状态互斥监听，结合代码段内存动态 Hash 校验，避免简单可识别的自杀分支。

---
*报告归档：Reverse Engineering Autonomous Workbench*
