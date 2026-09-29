package com.xiaoheihe;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.memory.Memory;
import unicorn.Arm64Const;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class XiaoHeiHeSignerRunner extends AbstractJni implements IOResolver {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final DalvikModule dm;
    private final Module module;
    private final DvmClass shaderManager;
    private final DvmObject<?> contextObj;

    public XiaoHeiHeSignerRunner() {
        System.out.println("[*] Initializing 64-bit Unidbg AndroidEmulator...");
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.max.xiaoheihe")
                .build();

        emulator.getSyscallHandler().addIOResolver(this);

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        File apkFile = new File("src/main/resources/app-release.apk");
        vm = emulator.createDalvikVM(apkFile);
        vm.setVerbose(false);
        vm.setJni(this);

        File soFile = new File("src/main/resources/libglesv3_1.so");
        dm = vm.loadLibrary(soFile, false);
        module = dm.getModule();
        dm.callJNI_OnLoad(emulator);

        shaderManager = vm.resolveClass("com/graphice/shaderar/ShaderManager");
        // Instantiate as ContextWrapper so methods resolved on ContextWrapper can be dispatched!
        contextObj = vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context")).newObject(null);

        System.out.println("[*] Native base address: 0x" + Long.toHexString(module.base));

        // Hook deliberate crashes and the infinite pthread spin-wait in setParseDepth!
        final long base = module.base;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long rel = address - base;
                // Crash 1: 0x1C5A28 -> skip crash and branch to 0x1C5AE4
                if (rel == 0x1C5A28L) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, base + 0x1C5AE4L);
                }
                // Crash 2: 0x1C5AD4 -> skip crash and branch to 0x1C5AE4
                else if (rel == 0x1C5AD4L) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, base + 0x1C5AE4L);
                }
                // Infinite Spin-Wait at 0x1C5C00-0x1C5C14: skip directly to 0x1C5C18!
                else if (rel == 0x1C5C00L) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, base + 0x1C5C18L);
                }
            }

            @Override
            public void onAttach(UnHook unHook) {}

            @Override
            public void detach() {}
        }, module.base + 0x1C5000L, module.base + 0x1C6000L, null);

        // Call setParseDepth to bootstrap container natively!
        System.out.println("[*] Calling ShaderManager.setParseDepth with all bypasses...");
        shaderManager.callStaticJniMethod(emulator, "setParseDepth(Ljava/lang/String;Z)V", new StringObject(vm, "init"), true);
        System.out.println("[+] setParseDepth completed! 0x218558 is now natively bootstrapped!");
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("android/content/Context->MODE_PRIVATE:I".equals(signature) || signature.contains("MODE_PRIVATE")) {
            return 0;
        }
        return super.getStaticIntField(vm, dvmClass, signature);
    }

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

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (signature.contains("getPackageName()")) {
            return new StringObject(vm, "com.max.xiaoheihe");
        }
        if (signature.contains("getFilesDir()")) {
            return vm.resolveClass("java/io/File").newObject(new File("/data/user/0/com.max.xiaoheihe/files"));
        }
        if (signature.contains("getPackageManager()")) {
            return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
        }
        if (signature.contains("getSharedPreferences(")) {
            return vm.resolveClass("android/content/SharedPreferences").newObject(null);
        }
        if (signature.contains("getString(")) {
            // Returns the stored debug_info / device id
            return new StringObject(vm, "000000000000000010000001");
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (signature.contains("getPackageName()")) {
            return new StringObject(vm, "com.max.xiaoheihe");
        }
        if (signature.contains("getFilesDir()")) {
            return vm.resolveClass("java/io/File").newObject(new File("/data/user/0/com.max.xiaoheihe/files"));
        }
        if (signature.contains("getPackageManager()")) {
            return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
        }
        if (signature.contains("getSharedPreferences(")) {
            return vm.resolveClass("android/content/SharedPreferences").newObject(null);
        }
        if (signature.contains("getString(")) {
            return new StringObject(vm, "000000000000000010000001");
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    public static class SignResult {
        public String path;
        public String _time;
        public String nonce;
        public String hkey;
        public String _rnd;
    }

    public SignResult sign(String path, long timestamp) {
        SignResult res = new SignResult();
        String strTime = String.valueOf(timestamp);
        String cleanPath = path.endsWith("/") ? path : (path + "/");
        res.path = cleanPath;
        res._time = strTime;

        // 1. Get ChunkFlag
        System.out.println("[*] Step 1: Getting ChunkFlag natively...");
        DvmObject<?> flagObj = shaderManager.callStaticJniMethodObject(
                emulator,
                "getChunkFlag(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
                contextObj,
                new StringObject(vm, "HPPDCEAENEHBFHPASRDCAMNHJLAAPF")
        );
        String chunkFlag = (String) flagObj.getValue();
        System.out.println("[+] ChunkFlag: " + chunkFlag);

        // 2. Call getIdxOffset to allocate real session Slot (nonce!)
        System.out.println("[*] Step 2: Calling getIdxOffset to mint genuine Nonce...");
        DvmObject<?> idxObj = shaderManager.callStaticJniMethodObject(
                emulator,
                "getIdxOffset(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                contextObj,
                new StringObject(vm, chunkFlag),
                new StringObject(vm, strTime),
                new StringObject(vm, "0000000000000000")
        );
        String idxOffset = (String) idxObj.getValue();
        res.nonce = idxOffset;
        System.out.println("[+] Genuine Nonce (idxOffset): " + idxOffset);

        // 3. Call full Setter chain
        System.out.println("[*] Step 3: Executing full Setter chain...");
        shaderManager.callStaticJniMethod(emulator, "setViewport(Ljava/lang/String;Ljava/lang/String;)V", new StringObject(vm, strTime), new StringObject(vm, idxOffset));
        shaderManager.callStaticJniMethod(emulator, "setGramLen(Ljava/lang/String;Ljava/lang/String;)V", new StringObject(vm, cleanPath), new StringObject(vm, idxOffset));
        shaderManager.callStaticJniMethod(emulator, "setBuf(Ljava/lang/String;Ljava/lang/String;)V", new StringObject(vm, strTime), new StringObject(vm, idxOffset));
        shaderManager.callStaticJniMethod(emulator, "setDepRel(Ljava/lang/String;Ljava/lang/String;)V", new StringObject(vm, "25102RKBEC"), new StringObject(vm, idxOffset));
        shaderManager.callStaticJniMethod(emulator, "setDLen(Ljava/lang/String;Ljava/lang/String;)V", new StringObject(vm, "14"), new StringObject(vm, idxOffset));
        shaderManager.callStaticJniMethod(emulator, "setPtrOffset(Ljava/lang/String;Ljava/lang/String;)V", new StringObject(vm, "1.3.385"), new StringObject(vm, idxOffset));

        // 4. Call getObjType for HKEY (isRnd = false)
        System.out.println("[*] Step 4: Calling getObjType for HKEY (isRnd = false)...");
        DvmObject<?> hkeyObj = shaderManager.callStaticJniMethodObject(
                emulator,
                "getObjType(Landroid/content/Context;Ljava/lang/String;Z)Ljava/lang/String;",
                contextObj,
                new StringObject(vm, idxOffset),
                false
        );
        res.hkey = (String) hkeyObj.getValue();
        System.out.println("[+] Genuine HKEY: " + res.hkey);

        // 5. Call getObjType for _RND (isRnd = true)
        System.out.println("[*] Step 5: Calling getObjType for _RND (isRnd = true)...");
        DvmObject<?> rndObj = shaderManager.callStaticJniMethodObject(
                emulator,
                "getObjType(Landroid/content/Context;Ljava/lang/String;Z)Ljava/lang/String;",
                contextObj,
                new StringObject(vm, idxOffset),
                true
        );
        String objType = (String) rndObj.getValue();
        res._rnd = "14:" + objType;
        System.out.println("[+] Genuine _RND: " + res._rnd);

        return res;
    }

    public static void main(String[] args) {
        try {
            XiaoHeiHeSignerRunner runner = new XiaoHeiHeSignerRunner();
            long now = System.currentTimeMillis() / 1000;
            SignResult r = runner.sign("/bbs/app/feeds/news", now);
            System.out.println("\n=======================================================");
            System.out.println("  100% UNIDBG GENUINE NATIVE SIGNATURE QUADRUPLE:");
            System.out.println("=======================================================");
            System.out.println("Path  : " + r.path);
            System.out.println("_time : " + r._time);
            System.out.println("nonce : " + r.nonce);
            System.out.println("hkey  : " + r.hkey);
            System.out.println("_rnd  : " + r._rnd);
            System.out.println("=======================================================\n");
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}

