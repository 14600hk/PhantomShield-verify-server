package tech.skidonion.obfuscator.transformer.impl;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.*;
import tech.skidonion.obfuscator.annotations.verification.LoadAfterLogin;
import tech.skidonion.obfuscator.asm.ClassWrapper;
import tech.skidonion.obfuscator.asm.CustomClassWriter;
import tech.skidonion.obfuscator.asm.FieldWrapper;
import tech.skidonion.obfuscator.asm.MethodWrapper;
import tech.skidonion.obfuscator.cpp.CppCompiler;
import tech.skidonion.obfuscator.crypto.ChaCha20;
import tech.skidonion.obfuscator.inline.Inline;
import tech.skidonion.obfuscator.inline.Wrapper;
import tech.skidonion.obfuscator.transformer.Transformer;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.*;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.bytecode.PreprocessorRunner;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.caches.CachedFieldInfo;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.caches.CachedMethodInfo;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.caches.NodeCache;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.snippets.Snippets;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.source.ClassSourceBuilder;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.source.InlineSourceBuilder;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.source.MainSourceBuilder;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.source.StringPool;
import tech.skidonion.obfuscator.transformer.impl.nativeobfuscation.verification.BufferContext;
import tech.skidonion.obfuscator.transformer.impl.renamer.Mapper;
import tech.skidonion.obfuscator.utils.*;
import tech.skidonion.obfuscator.utils.commons.Pair;
import tech.skidonion.obfuscator.utils.commons.PriorityObject;
import tech.skidonion.obfuscator.value.impls.BooleanValue;
import tech.skidonion.obfuscator.value.impls.ClassPackageValue;
import tech.skidonion.obfuscator.value.impls.StringValue;
import tech.skidonion.obfuscator.value.impls.SubValue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static tech.skidonion.obfuscator.PhantomShield.*;

@LoadAfterLogin(value = "基础用户组", priority = 1)
public class NativeObfuscation extends Transformer {
    public static final String INLINE_DECLARE = Type.getInternalName(Inline.class);
    public static final String INLINE_DESC = Type.getDescriptor(tech.skidonion.obfuscator.annotations.NativeObfuscation.Inline.class);
    public static final String OLD_INLINE_DESC = Type.getDescriptor(tech.skidonion.obfuscator.annotations.NativeObfuscation.InlineStaticFieldAccess.class);
    public static final String CLASS_ENCRYPTION_DESC = Type.getDescriptor(LoadAfterLogin.class);
    public final Map<String, MethodWrapper> injectedWrapperMethods = new HashMap<>();
    public final Map<String, Pair<String, FieldWrapper>> inlineFields = new HashMap<>();
    public final Map<String, Pair<String, MethodWrapper>> inlineMethods = new HashMap<>();
    private final BooleanValue print_instructions = new BooleanValue("print_instructions", true);
    private final ClassPackageValue loader_package = new ClassPackageValue("loader_package", "skidonion/??????");
    private final BooleanValue hidden_stack_trace = new BooleanValue("hidden_stack_trace", true);
    private final BooleanValue null_safety = new BooleanValue("null_safety", false);
    private final BooleanValue verification_enable = new BooleanValue("verification_enable", false);
    private final BooleanValue use_internal_user_interface = new BooleanValue("use_internal_user_interface", true);
    private final StringValue verification_server = new StringValue("verification_server", "https://skidonion.tech/");
    private final StringValue verification_user_id = new StringValue("verification_user_id", "-1");
    private final StringValue verification_software_id = new StringValue("verification_software_id", "-1");
    private final StringValue verification_token = new StringValue("verification_token", "");
    private final BooleanValue verification_keep_alive = new BooleanValue("verification_keep_alive", true);
    private final SubValue verification = new SubValue("verification", verification_enable, use_internal_user_interface, verification_server, verification_user_id, verification_software_id, verification_token, verification_keep_alive);

    public NativeObfuscation(String name) {
        super(name, false);
        addSettings(print_instructions, loader_package, hidden_stack_trace, null_safety, verification);
    }

    private Snippets snippets;
    private StringPool stringPool;
    private MethodProcessor methodProcessor;
    private NodeCache<String> cachedStrings;
    private NodeCache<String> cachedClasses;
    private NodeCache<String> cachedInitClasses;
    private NodeCache<CachedMethodInfo> cachedMethods;
    private NodeCache<CachedFieldInfo> cachedFields;
    private AtomicInteger cachedCallSitesIndex;
    private HiddenMethodsPool hiddenMethodsPool;
    private int currentClassId;
    private String nativeDir;

    private ClassWrapper dummyInlineClassWrapper;


    // verification
    private final Map<String, Pair<byte[], List<PriorityObject<ClassWrapper>>>> encryptedClasses = new HashMap<>();
    private final Map<String, BufferContext> verificationBuffer = new HashMap<>();

    private final byte[] sessionKey = new byte[16];
    private final byte[] nonce = new byte[12];
    private final Map<String, byte[]> magicKey = new HashMap<>();

    private void init() {
        stringPool = new StringPool();
        snippets = new Snippets(stringPool, null_safety.isEnable());
        cachedStrings = new NodeCache<>("(cstrings[%d])");
        cachedClasses = new NodeCache<>("(cclasses[%d])");
        cachedMethods = new NodeCache<>("(cmethods[%d])");
        cachedFields = new NodeCache<>("(cfields[%d])");
        cachedInitClasses = new NodeCache<>("(cinits[%d])");
        methodProcessor = new MethodProcessor(this);
        nativeDir = loader_package.getValue();
        nativeDir = nativeDir.substring(0, nativeDir.length() - 1);

        ThreadLocalRandom.current().nextBytes(sessionKey);
        ThreadLocalRandom.current().nextBytes(nonce);
    }


    @Override
    public void postprocess() throws Exception {
        Path cppDir = print_instructions.isEnable() ? new File(obfuscator.getConfig().getString("output")).getParentFile().toPath() : Files.createTempDirectory(null);
        CppCompiler compiler = obfuscator.getCompiler();
        compiler.setOutputDir(cppDir.toFile());

        FileUtils.copyResource("sources/jni.h", cppDir);
        FileUtils.copyResource("sources/jni_md.h", cppDir);
        FileUtils.copyResource("sources/native_jvm.cpp", cppDir);
        FileUtils.copyResource("sources/native_jvm.hpp", cppDir);
        FileUtils.copyResource("sources/native_jvm_output.hpp", cppDir);
        FileUtils.copyResource("sources/string_pool.hpp", cppDir);
        compiler.addCppFile(cppDir.resolve("native_jvm.cpp").toAbsolutePath().toString());
        compiler.addCppFile(cppDir.resolve("string_pool.cpp").toAbsolutePath().toString());
        compiler.addCppFile(cppDir.resolve("native_jvm_output.cpp").toAbsolutePath().toString());

//        CMakeFilesBuilder cMakeBuilder = new CMakeFilesBuilder(projectName);
//        cMakeBuilder.addMainFile("native_jvm.hpp");
//        cMakeBuilder.addMainFile("native_jvm.cpp");
//        cMakeBuilder.addMainFile("native_jvm_output.hpp");
//        cMakeBuilder.addMainFile("native_jvm_output.cpp");
//        cMakeBuilder.addMainFile("string_pool.hpp");
//        cMakeBuilder.addMainFile("string_pool.cpp");

        MainSourceBuilder mainSourceBuilder = new MainSourceBuilder();

        InlineSourceBuilder inlineSourceBuilder = new InlineSourceBuilder(this, compiler, stringPool);

        hiddenMethodsPool = new HiddenMethodsPool(nativeDir + "/___");

        Optional<String> opt = Wrapper.getCloudConstant(271423823, 0);

        final boolean[] internalTip = {false};

        Integer[] classIndexReference = new Integer[]{0};
        getFilteredClasses().forEach(cw -> {
            boolean clinitIgnoreTryCatch = false;
            String clinitVirtualization = "NONE";
            String clinitLock = null;
            {
                Map<String, Object> map = getAnnotationValues(cw);
                removeAnnotation(cw);
                if (map != null) {
                    Object virtualize = map.get("virtualize");
                    if (virtualize instanceof String[]) {
                        clinitVirtualization = ((String[]) virtualize)[1];
                        compiler.getVirtualizeMacroCount().getAndIncrement();
                    }
                    Object ignoreTryCatch = map.get("manualTryCatch");
                    if (ignoreTryCatch instanceof Boolean) {
                        clinitIgnoreTryCatch = (boolean) ignoreTryCatch;
                    }
                    Object lock = map.get("verificationLock");
                    if (lock instanceof String) {
                        clinitLock = (String) lock;
                    }
                }
            }
            try {
                addInternalInclusion(cw.getOriginalName(), "<clinit>()V");
                cw.getOrCreateClinit();
                StringBuilder nativeMethods = new StringBuilder();
                List<HiddenCppMethod> hiddenMethods = new ArrayList<>();
                String displayName = cw.getOriginalName();
                boolean isInternal = displayName.startsWith("tech/skidonion/verification/");
                if (isInternal) {
                    if (!internalTip[0]) {
                        displayName = "[Internal Classes]";
                        internalTip[0] = true;
                    } else {
                        displayName = null;
                    }
                }

                if (displayName != null) INFO(TRANSLATION("phantom-shield-x.native.covert"), displayName);

                Stream<MethodNode> antiLowIq =
                        cw.getMethods().stream().filter(this::match)
                                .map(MethodWrapper::getMethodNode);
                List<MethodNode> methods = antiLowIq.collect(Collectors.toList());
                if (methods.size() <= 1 && displayName != null) {
                        WARN(TRANSLATION("phantom-shield-x.native.no-methods"), displayName);
                }
                methods.stream().filter(MethodProcessor::shouldProcess).forEach(PreprocessorRunner::preprocess);


                CustomClassWriter computedWriter = new CustomClassWriter(Opcodes.ASM9 | ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, obfuscator);
                cw.getClassNode().accept(computedWriter);

                ClassReader computedReader = new ClassReader(computedWriter.toByteArray());
                ClassNode computedClassNode = new ClassNode(Opcodes.ASM9);
                computedReader.accept(computedClassNode, 0);
                if (opt.isPresent() && (Integer.parseInt(opt.get()) ^ 1825605542) == 1789160537) {
                    IntStream.range(0, computedClassNode.methods.size())
                            .forEach(i -> cw.getMethods().get(i).setMethodNode(computedClassNode.methods.get(i)));
                    IntStream.range(0, computedClassNode.fields.size())
                            .forEach(i -> cw.getFields().get(i).setFieldNode(computedClassNode.fields.get(i)));
                }

                cw.setClassNode(computedClassNode);

                cachedInitClasses.clear();
                cachedStrings.clear();
                cachedClasses.clear();
                cachedMethods.clear();
                cachedFields.clear();
                cachedCallSitesIndex = new AtomicInteger();

                ClassSourceBuilder cppBuilder =
                        new ClassSourceBuilder(this, cw.getName(), classIndexReference[0]++, stringPool);
//                    compiler.addCppFile(cppBuilder.getCppFile().toAbsolutePath().toString());
                StringBuilder instructions = new StringBuilder();

                Set<String> headers = new HashSet<>();

                boolean shouldVirtualize = false;
                for (int i = 0; i < cw.getMethods().size(); i++) {
                    MethodWrapper method = cw.getMethods().get(i);

                    if (!MethodProcessor.shouldProcess(method.getMethodNode()) || !match(method)) {
                        continue;
                    }
                    MethodContext context = new MethodContext(this, method, i, cw, currentClassId);
                    Map<String, Object> map = getAnnotationValues(method);
                    removeAnnotation(method);
                    if (map != null) {
                        Object virtualize = map.get("virtualize");
                        if (virtualize instanceof String[]) {
                            shouldVirtualize = true;
                            context.virtualization = ((String[]) virtualize)[1];
                            compiler.getVirtualizeMacroCount().getAndIncrement();
                        }
                        Object ignoreTryCatch = map.get("manualTryCatch");
                        if (ignoreTryCatch instanceof Boolean) {
                            context.manualTryCatch = (boolean) ignoreTryCatch;
                        }
                        Object lock = map.get("verificationLock");
                        if (lock instanceof String) {
                            BufferContext buffer;
                            if ((buffer = verificationBuffer.get(lock)) != null) {
                                context.verificationLock = buffer;
                            }
                        }
                    }
                    if ("<clinit>".equals(method.getName())) {
                        if (!"NONE".equals(clinitVirtualization)) {
                            shouldVirtualize = true;
                            context.virtualization = clinitVirtualization;
                        }
                        context.manualTryCatch = clinitIgnoreTryCatch;
                        BufferContext buffer;
                        if ((buffer = verificationBuffer.get(clinitLock)) != null) {
                            context.verificationLock = buffer;
                        }
                    }
                    if (opt.isPresent() && (Integer.parseInt(opt.get()) ^ 1825605542) == 1789160537)
                        methodProcessor.processMethod(context);
                    shouldVirtualize |= context.shouldVirtualize;

                    headers.addAll(context.headers);

                    instructions.append(context.output.toString().replace("\n", "\n    "));

                    nativeMethods.append(context.nativeMethods);

                    if (context.proxyMethod != null) {
                        hiddenMethods.add(new HiddenCppMethod(context.proxyMethod, context.cppNativeMethodName));
                    }

                    if ((computedClassNode.access & Opcodes.ACC_INTERFACE) > 0) {
                        method.getMethodNode().access &= ~Opcodes.ACC_NATIVE;
                    }
                }

                shouldVirtualize |= isVerificationEnable();

                cppBuilder.addHeader(cachedStrings.size(), cachedClasses.size(), cachedMethods.size(), cachedFields.size(), cachedCallSitesIndex.get(), cachedInitClasses.size());
                cppBuilder.addInstructions(instructions.toString());
                cppBuilder.registerMethods(cw, cachedStrings, cachedClasses, nativeMethods.toString(), hiddenMethods, shouldVirtualize, isInternal);

                if (shouldVirtualize) {
                    if (compiler.isAdvancedModuleEnable()) {
                        mainSourceBuilder.addHeader("\"ThemidaSDK.h\"");
                    } else {
                        mainSourceBuilder.addHeader("\"VirtualizerSDK.h\"");
                    }
                }
//                    cMakeBuilder.addClassFile("output/" + cppBuilder.getHppFilename());
//                    cMakeBuilder.addClassFile("output/" + cppBuilder.getCppFilename());

                mainSourceBuilder.addHeaders(headers);
                mainSourceBuilder.addConvertedCode(cppBuilder.build());
                mainSourceBuilder.registerClassMethods(currentClassId, cppBuilder.getFilename());


                currentClassId++;
            } catch (IOException ex) {
                ERROR(TRANSLATION("phantom-shield-x.native.error"), cw.getOriginalName(), ex);
            }

        });

        Set<String> headers = new HashSet<>();
        StringBuilder instructions = new StringBuilder();
        StringBuilder declarations = new StringBuilder();
        boolean shouldVirtualize = false;

        cachedStrings.clear();
        cachedClasses.clear();
        cachedMethods.clear();
        cachedFields.clear();
        cachedInitClasses.clear();
        cachedCallSitesIndex = new AtomicInteger();

        if (!inlineMethods.isEmpty()) {
            INFO(TRANSLATION("phantom-shield-x.native.inline-methods"));


            inlineMethods.values().stream()
                    .map(Pair::getSecond)
                    .forEach(mw -> PreprocessorRunner.preprocess(mw.getMethodNode()));


            CustomClassWriter computedWriter = new CustomClassWriter(Opcodes.ASM9 | ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, obfuscator);
            dummyInlineClassWrapper.getClassNode().accept(computedWriter);

            ClassReader computedReader = new ClassReader(computedWriter.toByteArray());
            ClassNode computedClassNode = new ClassNode(Opcodes.ASM9);
            computedReader.accept(computedClassNode, 0);

            if (opt.isPresent() && (Integer.parseInt(opt.get()) ^ 1825605542) == 1789160537) {
                IntStream.range(0, computedClassNode.methods.size())
                        .forEach(i -> dummyInlineClassWrapper.getMethods().get(i).setMethodNode(computedClassNode.methods.get(i)));
                IntStream.range(0, computedClassNode.fields.size())
                        .forEach(i -> dummyInlineClassWrapper.getFields().get(i).setFieldNode(computedClassNode.fields.get(i)));
                dummyInlineClassWrapper.setClassNode(computedClassNode);
            }
            Map<MethodWrapper, String> inlineMethodsBi = new HashMap<>();
            for (Map.Entry<String, Pair<String, MethodWrapper>> stringPairEntry : inlineMethods.entrySet()) {
                inlineMethodsBi.put(stringPairEntry.getValue().getSecond(), stringPairEntry.getValue().getFirst());
            }


            for (int i = 0; i < dummyInlineClassWrapper.getMethods().size(); i++) {
                MethodWrapper method = dummyInlineClassWrapper.getMethods().get(i);
                MethodContext context = new MethodContext(this, method, i, method.getOwner(), currentClassId);
                Map<String, Object> map = getAnnotationValues(method);
                removeAnnotation(method);
                if (map != null) {
                    Object virtualize = map.get("virtualize");
                    if (virtualize instanceof String[]) {
                        shouldVirtualize = true;
                        context.virtualization = ((String[]) virtualize)[1];
                        compiler.getVirtualizeMacroCount().getAndIncrement();
                    }
                    Object ignoreTryCatch = map.get("manualTryCatch");
                    if (ignoreTryCatch instanceof Boolean) {
                        context.manualTryCatch = (boolean) ignoreTryCatch;
                    }
                    Object lock = map.get("verificationLock");
                    if (lock instanceof String) {
                        BufferContext buffer;
                        if ((buffer = verificationBuffer.get(lock)) != null) {
                            context.verificationLock = buffer;
                        }
                    }
                }
                String cname;
                context.cppNativeMethodName = (cname = inlineMethodsBi.get(method)) != null ? cname : null;
                if (opt.isPresent() && (Integer.parseInt(opt.get()) ^ 1825605542) == 1789160537)
                    methodProcessor.processMethod(context);
                shouldVirtualize |= context.shouldVirtualize;

                headers.addAll(context.headers);

                instructions.append(context.output.toString().replace("\n", "\n    "));
                declarations.append(context.export.toString());
            }

            shouldVirtualize |= isVerificationEnable();

        }

        // process encrypted classes
        StringBuilder encryptedClassBuilder = new StringBuilder();

        if (!encryptedClasses.isEmpty()) {
            INFO(TRANSLATION("phantom-shield-x.native.encrypted-classes"));


            for (Pair<byte[], List<PriorityObject<ClassWrapper>>> pair : encryptedClasses.values()) {
                byte[] key = pair.getFirst();

                List<PriorityObject<ClassWrapper>> list = pair.getSecond();

                ChaCha20 crypto = new ChaCha20(key, nonce, 4096);
                for (PriorityObject<ClassWrapper> priorityObject : list) {
                    ClassWrapper classWrapper = priorityObject.getObject();

                    String classFileName = "data_" + StringUtils.escapeCppNameString(classWrapper.getName().replace('/', '_'));

//                    headers.add("\"output/" + classFileName + ".hpp\"");

                    CustomClassWriter classWriter = new CustomClassWriter(Opcodes.ASM9 | ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, obfuscator);
                    classWrapper.getClassNode().accept(classWriter);
                    byte[] rawData = classWriter.toByteArray();
                    byte[] dst = new byte[rawData.length];
                    crypto.encrypt(dst, rawData, rawData.length);
                    List<Byte> data = new ArrayList<>(dst.length);
                    for (byte b : dst) {
                        data.add(b);
                    }

                    encryptedClassBuilder.append("namespace native_jvm::data::__ngen_").append(classFileName).append(" {\n");
                    encryptedClassBuilder.append("    static const jbyte class_data[").append(data.size()).append("] = { ");
                    encryptedClassBuilder.append(data.stream().map(String::valueOf).collect(Collectors.joining(", ")));
                    encryptedClassBuilder.append("};\n");
                    encryptedClassBuilder.append("    static const jsize class_data_length = ").append(data.size()).append(";\n\n");
                    encryptedClassBuilder.append("    const jbyte* get_class_data() { return class_data; }\n");
                    encryptedClassBuilder.append("    const jsize get_class_data_length() { return class_data_length; }\n");
                    encryptedClassBuilder.append("}\n\n");


                    for (MethodWrapper method : classWrapper.getMethods()) {
                        MethodNode methodNode = method.getMethodNode();
                        methodNode.access &= ~(ACC_NATIVE | ACC_ABSTRACT);
                        InsnList insnList = new InsnList();
                        insnList.add(new TypeInsnNode(NEW, "java/lang/IllegalStateException"));
                        insnList.add(new InsnNode(DUP));
                        insnList.add(new LdcInsnNode("This Exception shouldn't appear! Please contact the software admin."));
                        insnList.add(new MethodInsnNode(INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;)V"));
                        insnList.add(new InsnNode(ATHROW));
                        methodNode.instructions = insnList;
                        methodNode.tryCatchBlocks = null;
                        methodNode.localVariables = null;
                        methodNode.visibleLocalVariableAnnotations = null;
                        methodNode.invisibleLocalVariableAnnotations = null;
                        methodNode.invisibleTypeAnnotations = null;
                        methodNode.visibleTypeAnnotations = null;
                    }
                }
            }
        }


        inlineSourceBuilder.buildHeader(headers, shouldVirtualize);
        inlineSourceBuilder.buildEncryptedClasses(encryptedClassBuilder);
        inlineSourceBuilder.buildInlineFields();
        inlineSourceBuilder.buildInlineMethods(instructions.toString(), declarations.toString(), cachedStrings, cachedClasses.size(), cachedMethods.size(), cachedFields.size(), cachedCallSitesIndex.get(), cachedInitClasses.size(), shouldVirtualize);
        inlineSourceBuilder.buildVerificationField();
        inlineSourceBuilder.buildTail();


        if (hidden_stack_trace.isEnable()) {
            for (ClassNode hiddenClass : hiddenMethodsPool.getClasses()) {

                String hiddenClassFileName = "data_" + StringUtils.escapeCppNameString(hiddenClass.name.replace('/', '_'));

//            cMakeBuilder.addClassFile("output/" + hiddenClassFileName + ".hpp");
//            cMakeBuilder.addClassFile("output/" + hiddenClassFileName + ".cpp");

//                mainSourceBuilder.addHeader(hiddenClassFileName + ".hpp");
                mainSourceBuilder.registerDefine(stringPool.get(hiddenClass.name), hiddenClassFileName);

                CustomClassWriter classWriter = new CustomClassWriter(Opcodes.ASM9 | ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, obfuscator);
                hiddenClass.accept(classWriter);
                byte[] rawData = classWriter.toByteArray();
                List<Byte> data = new ArrayList<>(rawData.length);
                for (byte b : rawData) {
                    data.add(b);
                }
                StringBuilder codes = new StringBuilder();
                codes.append("namespace native_jvm::data::__ngen_").append(hiddenClassFileName).append(" {\n");
                codes.append("    static const jbyte class_data[").append(String.valueOf(data.size())).append("] = { ");
                codes.append(data.stream().map(String::valueOf).collect(Collectors.joining(", ")));
                codes.append("};\n");
                codes.append("    static const jsize class_data_length = ").append(String.valueOf(data.size())).append(";\n\n");
                codes.append("    const jbyte* get_class_data() { return class_data; }\n");
                codes.append("    const jsize get_class_data_length() { return class_data_length; }\n");
                codes.append("}\n");
                mainSourceBuilder.addConvertedCode(codes.toString());
            }
        } else {
            injectClassesAsResource(hiddenMethodsPool.getClasses());
        }

        Files.write(cppDir.resolve("string_pool.cpp"), stringPool.build().getBytes(StandardCharsets.UTF_8));
        Files.write(cppDir.resolve("native_jvm_inline.cpp"), inlineSourceBuilder.buildCpp().getBytes(StandardCharsets.UTF_8));
        Files.write(cppDir.resolve("native_jvm_inline.hpp"), inlineSourceBuilder.buildHpp().getBytes(StandardCharsets.UTF_8));

        mainSourceBuilder.addAdditionCode("        inlines::init(env);");
        Files.write(cppDir.resolve("native_jvm_output.cpp"), mainSourceBuilder.build(nativeDir, currentClassId).getBytes(StandardCharsets.UTF_8));

        compiler.addCppFile(cppDir.resolve("native_jvm_inline.cpp").toAbsolutePath().toString());

        if (compiler.getVirtualizeMacroCount().get() > 0) {
            if (compiler.isAdvancedModuleEnable()) {
                FileUtils.copyResource("sources/ThemidaSDK.h", cppDir);
                FileUtils.copyResource("sources/SecureEngineCustomVMs.h", cppDir);
                FileUtils.copyResource("sources/SecureEngineCustomVMs_BorlandC_inline.h", cppDir);
                FileUtils.copyResource("sources/SecureEngineCustomVMs_GNU_inline.h", cppDir);
                FileUtils.copyResource("sources/SecureEngineCustomVMs_ICL_inline.h", cppDir);
                FileUtils.copyResource("sources/SecureEngineCustomVMs_LCC_inline.h", cppDir);
                FileUtils.copyResource("sources/SecureEngineCustomVMs_VC_inline.h", cppDir);
            } else {
                FileUtils.copyResource("sources/VirtualizerSDK.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_BorlandC_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_CustomVMs.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_CustomVMs_BorlandC_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_CustomVMs_GNU_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_CustomVMs_ICL_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_CustomVMs_LCC_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_CustomVMs_VC_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_GNU_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_ICL_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_LCC_inline.h", cppDir);
                FileUtils.copyResource("sources/VirtualizerSDK_VC_inline.h", cppDir);
            }
        }

        compiler.compile(StringUtils.createStringMap("loader_path", nativeDir));

        if (!print_instructions.isEnable()) {
            FileUtils.clearDirectory(cppDir);
        }
    }

    @Override
    public void transform() throws Exception {
        ArrayList<String> cacheArray = new ArrayList<>();

        // check role
        Optional<String> opt = Wrapper.getCloudConstant(467287013, 0);


        // check if it has permission to access verification
        // request software information
        List<ClassWrapper> injected = new ArrayList<>();
        long verifySoftwareId;
        byte[] verifyPublicKey;
        String verifyVersion;
        boolean verifyShouldCheckHwid;
        if (isVerificationEnable() && opt.isPresent() && (Integer.parseInt(opt.get()) ^ 173359771) == 2082061244) {
            verifySoftwareId = 123456789L;
            verifyPublicKey = "verifyPublicKey".getBytes();
            verifyVersion = "1.0";
            verifyShouldCheckHwid = true;
            magicKey.put("Rank", "magicKey".getBytes());

            // inject verification class
            INFO(TRANSLATION("phantom-shield-x.native.software"), "SomeRandomAppName");

            List<ClassWrapper> classes = injectClasses(ASMUtils.readClassesWithInputStream("/binaries/phantomshield-verification.bin", ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES));

            InternalClasses.inject(this, classes);

            for (ClassWrapper cw : classes) {
                obfuscator.buildHierarchy(cw, null);
                String origin = cw.getOriginalName();
                addInternalInclusion(origin, "*");
                for (MethodWrapper mw : cw.getMethods()) {
                    injectedWrapperMethods.put(origin + "." + mw.getOriginalName() + mw.getOriginalDescription(), mw);
                }
            }
            injected.addAll(classes);
            injectResources(IOUtils.readJarResources("/binaries/phantomshield-verification.bin"));
        } else {
            verifySoftwareId = -1L;
            verifyPublicKey = new byte[0];
            verifyVersion = "";
            verifyShouldCheckHwid = true;
        }


        // process for annotations
        AtomicInteger inlineFieldIndex = new AtomicInteger();
        AtomicInteger verificationLockIndex = new AtomicInteger();

        getClassWrappers().forEach(classWrapper -> {

            if (isVerificationEnable() && ASMUtils.hasAnnotation(classWrapper, CLASS_ENCRYPTION_DESC)) {
                Map<String, Object> values = ASMUtils.getAnnotationValues(classWrapper, CLASS_ENCRYPTION_DESC);
                ASMUtils.removeAnnotation(classWrapper, CLASS_ENCRYPTION_DESC);
                if (values != null) {
                    Object value = values.get("value");
                    Object priority = values.getOrDefault("priority", 0);
                    if (value instanceof String && priority instanceof Integer && isVerificationEnable()) {
                        if (magicKey.containsKey(value)) {
                            encryptedClasses.compute((String) value, (k, v) -> {
                                Pair<byte[], List<PriorityObject<ClassWrapper>>> pair;
                                if ((pair = v) == null) {
                                    byte[] des = new byte[32];
                                    byte[] magic = magicKey.get(value);

                                    for (int i = des.length - 1; i >= 0; i--) {
                                        int index = i / 2;
                                        int position = index % 2;
                                        if (i % 2 == 0) {
                                            des[i] = magic[index + (position == 1 ? -1 : 1)];
                                        } else {
                                            des[i] = sessionKey[index + (position == 1 ? -1 : 1)];
                                        }
                                    }
                                    byte temp = des[0];
                                    des[0] = des[des.length - 1];
                                    des[des.length - 1] = temp;

                                    pair = new Pair<>(des, new ArrayList<>());
                                }
                                pair.getSecond().add(new PriorityObject<>(classWrapper, (int) priority));
                                return pair;
                            });
                        } else {
                            ERROR(TRANSLATION("phantom-shield-x.native.class-lock.role-not-found"), value);
                            System.exit(0);
                            return;
                        }
                    }
                } else {
                    ERROR(TRANSLATION("phantom-shield-x.native.class-lock.annotation-error"));
                    System.exit(0);
                    return;
                }
            }

            boolean isCloseable;
            if (classWrapper.getInterfaces() != null) {
                Set<String> interfaces = new HashSet<>(classWrapper.getInterfaces());
                isCloseable = interfaces.contains("java/lang/AutoCloseable") || interfaces.contains("java/io/Closeable");
            } else {
                isCloseable = false;
            }

            Set<String> inlineVirtualFields = new HashSet<>();
            int i = 0;
            for (Iterator<FieldWrapper> iterator = classWrapper.getFields().iterator(); iterator.hasNext(); i++) {
                FieldWrapper fieldWrapper = iterator.next();
                boolean oldAnnotation = ASMUtils.hasAnnotation(fieldWrapper, OLD_INLINE_DESC);
                if (ASMUtils.hasAnnotation(fieldWrapper, INLINE_DESC) || oldAnnotation) {
                    String key = classWrapper.getName() + "." + fieldWrapper.getName() + "." + fieldWrapper.getDescription();
                    if (!fieldWrapper.getAccess().isStatic()) {
                        inlineVirtualFields.add(key);
                    } else if (oldAnnotation) {
                        WARN(TRANSLATION("phantom-shield-x.native.inline-deprecated"));
                    }

                    System.out.println("inline field:  " + key);
                    String name = "__phantom_shield_x_" + StringUtils.escapeCppNameString(fieldWrapper.getName().replace('/', '_')) + inlineFieldIndex.getAndIncrement();
                    cacheArray.add(key);
                    cacheArray.add(name);
                    inlineFields.put(key, new Pair<>(name, fieldWrapper));
                    iterator.remove();
                    classWrapper.getClassNode().fields.remove(i--);
                }
            }

            boolean shouldAddGarbageCollection = isCloseable && !inlineVirtualFields.isEmpty();
            if (shouldAddGarbageCollection) {
                addInternalInclusion(classWrapper.getOriginalName(), "close()V");
            }

            i = 0;
            for (Iterator<MethodWrapper> iterator = classWrapper.getMethods().iterator(); iterator.hasNext(); i++) {
                MethodWrapper methodWrapper = iterator.next();

                if (hasAnnotation(methodWrapper)) {
                    Map<String, Object> map = getAnnotationValues(methodWrapper);
                    if (map != null) {
                        Object lock = map.get("verificationLock");
                        if (lock instanceof String && isVerificationEnable()) {
                            if (!magicKey.containsKey(lock)) {
                                ERROR(TRANSLATION("phantom-shield-x.native.role-error"));
                                System.exit(0);
                            } else if (!verificationBuffer.containsKey(lock)) {
                                byte[] key = encryptedClasses.computeIfAbsent((String) lock, k -> {
                                    byte[] des = new byte[32];
                                    byte[] magic = magicKey.get(k);

                                    for (int _i = des.length - 1; _i >= 0; _i--) {
                                        int index = _i / 2;
                                        int position = index % 2;
                                        if (_i % 2 == 0) {
                                            des[_i] = magic[index + (position == 1 ? -1 : 1)];
                                        } else {
                                            des[_i] = sessionKey[index + (position == 1 ? -1 : 1)];
                                        }
                                    }
                                    byte temp = des[0];
                                    des[0] = des[des.length - 1];
                                    des[des.length - 1] = temp;

                                    return new Pair<>(des, new ArrayList<>());
                                }).getFirst();
                                byte[] src = new byte[256];
                                byte[] dst = new byte[256];
                                byte[] s = new byte[256];
                                ThreadLocalRandom.current().nextBytes(src);
                                System.arraycopy(src, 0, dst, 0, src.length);
                                generate_key:
                                {
                                    int _i, _j = 0;
                                    byte[] k = new byte[256];
                                    byte tmp;
                                    for (_i = 0; _i < 256; _i++) {
                                        s[_i] = (byte) _i;
                                        k[_i] = key[_i % 32];
                                    }
                                    for (_i = 0; _i < 256; _i++) {
                                        _j = (_j + s[_i] + k[_i]) & 0xFF;
                                        tmp = s[_i];
                                        s[_i] = s[_j];
                                        s[_j] = tmp;
                                    }
                                }

                                encrypt_buffer:
                                {
                                    int _i = 0, _j = 0, _t;
                                    byte tmp;
                                    for (int _k = 0; _k < 256; _k++) {
                                        _j = (_j + s[_i]) & 0xFF;
                                        tmp = s[_i];
                                        s[_i] = s[_j];
                                        s[_j] = tmp;
                                        _t = (s[_i] + s[_j]) & 0xFF;
                                        dst[_k] = (byte) (dst[_k] ^ (int) s[_t]);
                                        _i = (_i + 1) & 0xFF;
                                    }
                                }
//                                System.out.println(Arrays.toString(src));

                                verificationBuffer.put((String) lock, new BufferContext(verificationLockIndex.getAndIncrement(), src, dst));
                            }
                        }
                    }
                }

                if (shouldAddGarbageCollection && Objects.equals("close()V", methodWrapper.getOriginalName() + methodWrapper.getOriginalDescription())) {
                    InsnList instructions = methodWrapper.getInstructions();
                    for (String inlineVirtualField : inlineVirtualFields) {
                        InsnList insnList = new InsnList();
                        insnList.add(new VarInsnNode(ALOAD, 0));
                        insnList.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_field_-" + inlineVirtualField, "(Ljava/lang/Object;)V", false));
                        instructions.insert(insnList);
                    }
                } else if (ASMUtils.hasAnnotation(methodWrapper, INLINE_DESC)) {
                    if (classWrapper.getAccess().isInterface()) {
                        ERROR(TRANSLATION("phantom-shield-x.native.inline-methods-interface-error"));
                        System.exit(0);
                        return;
                    }
                    if (methodWrapper.hasInstructions()) {
                        String key = classWrapper.getName() + "." + methodWrapper.getName() + methodWrapper.getDescription();
//                    inlineMethods.put(key, new Pair<>("__phantom_shield_x_" + StringUtils.escapeCppNameString(methodWrapper.getName().replace('/', '_')) + inlineFieldIndex.getAndIncrement(), methodWrapper));
                        System.out.println("inline method:  " + key);
                        String name = "__phantom_shield_x_" + inlineFieldIndex.getAndIncrement();
//                        cacheArray.add(key);
//                        cacheArray.add(name);
                        inlineMethods.put(key, new Pair<>(name, methodWrapper));
//                    addInternalInclusion(classWrapper.getOriginalName(), methodWrapper.getOriginalName() + methodWrapper.getOriginalDescription());
                        iterator.remove();
                        classWrapper.getClassNode().methods.remove(i--);
                    } else {
                        ASMUtils.removeAnnotation(methodWrapper, INLINE_DESC);
                    }
                }
            }
        });
        System.out.println("\n\n\n\n");
        for (String str : cacheArray) {
            System.out.println(str);
        }
        System.out.println("\n\n\n\n");
        // sort for encryptedClasses
        for (Pair<byte[], List<PriorityObject<ClassWrapper>>> pair : encryptedClasses.values()) {
            List<PriorityObject<ClassWrapper>> list = pair.getSecond();
            Collections.sort(list);
        }

        // make wrapper class for inline where can't force inline to native code
        final ClassNode wrapper = new ClassNode();
        wrapper.version = V1_8;
        wrapper.access = ACC_PUBLIC;
        wrapper.superName = "java/lang/Object";
        wrapper.name = "tech/skidonion/verification/InlineWrapper";
//        ClassWrapper inline = injectClass(wrapper);
        ClassWrapper inline = new ClassWrapper(obfuscator, wrapper, false, null);
        AtomicInteger inlineIndex = new AtomicInteger();
        addInternalInclusion(wrapper.name, "*");


        // make inline dummy class
        ClassNode dummyClass = new ClassNode();
        dummyClass.name = "_PHANTOMSHIELD_X_INLINE_DUMMY";
        dummyClass.version = V1_8;
        dummyClass.superName = "java/lang/Object";
        dummyClass.access = ACC_PUBLIC | ACC_SUPER;
        dummyInlineClassWrapper = new ClassWrapper(obfuscator, dummyClass, false, null);

        inlineMethods.values().stream()
                .map(Pair::getSecond)
                .forEach(dummyInlineClassWrapper::addMethod);

        addInternalInclusion(dummyClass.name, "*");

        ArrayList<ClassWrapper> classWrappers = new ArrayList<ClassWrapper>(getClassWrappers()) {
            {
                add(dummyInlineClassWrapper);
            }
        };

        // process wrapper first

        classWrappers.forEach(classWrapper -> {
            classWrapper.getMethods().forEach(methodWrapper -> {
                for (ListIterator<AbstractInsnNode> iterator = methodWrapper.getMethodNode().instructions.iterator(); iterator.hasNext(); ) {
                    AbstractInsnNode instruction = iterator.next();
                    if (instruction instanceof MethodInsnNode) {
                        MethodInsnNode methodInsnNode = (MethodInsnNode) instruction;
                        String reference = methodInsnNode.owner + "." + methodInsnNode.name + methodInsnNode.desc;
                        switch (reference) {
                            case "tech/skidonion/obfuscator/inline/Wrapper.getVerifyToken()Ljava/lang/String;":
                            case "tech/skidonion/obfuscator/inline/Wrapper.setAsSuspected(Ljava/lang/String;)V":
                            case "tech/skidonion/obfuscator/inline/Wrapper.getCloudConstant(II)Ljava/util/Optional;":
                            case "tech/skidonion/obfuscator/inline/Wrapper.getExpiredDate(Ljava/lang/String;)Ljava/util/Optional;":
                            case "tech/skidonion/obfuscator/inline/Wrapper.getExpiredDates()Ljava/util/Map;":
                            case "tech/skidonion/obfuscator/inline/Wrapper.hasRole(Ljava/lang/String;)Z":
                            case "tech/skidonion/obfuscator/inline/Wrapper.getUsername()Ljava/util/Optional;":
                            case "tech/skidonion/obfuscator/inline/Wrapper.getUserId()Ljava/util/Optional;": {
                                if (!opt.isPresent() || (Integer.parseInt(opt.get()) ^ 173359771) != 2082061244)
                                    break;
                                iterator.remove();
                                iterator.add(new MethodInsnNode(INVOKESTATIC, "tech/skidonion/verification/utils/VerifyUtils", methodInsnNode.name, methodInsnNode.desc, false));
                                break;
                            }
                            case "tech/skidonion/obfuscator/inline/Wrapper.login(Ljava/lang/String;Ljava/lang/String;Z)I": {
                                if (!opt.isPresent() || (Integer.parseInt(opt.get()) ^ 173359771) != 2082061244)
                                    break;
                                iterator.remove();
                                iterator.add(new MethodInsnNode(INVOKESTATIC, "tech/skidonion/verification/utils/VerifyUtils", methodInsnNode.name, methodInsnNode.desc, false));
                                iterator.add(new IntInsnNode(BIPUSH, 8));
                                iterator.add(new InsnNode(ISHR));
                                iterator.add(new IntInsnNode(SIPUSH, 255));
                                iterator.add(new InsnNode(IAND));
                                iterator.add(new InsnNode(I2B));
                                break;
                            }
                        }
                    }
                }
            });
        });

        // then process for inline


        classWrappers.forEach(classWrapper -> {
            final boolean classMatch = match(classWrapper);
            classWrapper.getMethods().forEach(methodWrapper -> {
                final boolean methodMatch = match(methodWrapper);
                final boolean obfuscated = (classMatch && methodMatch || classWrapper == dummyInlineClassWrapper) && !"<init>".equals(methodWrapper.getOriginalName());

                for (ListIterator<AbstractInsnNode> iterator = methodWrapper.getMethodNode().instructions.iterator(); iterator.hasNext(); ) {
                    AbstractInsnNode instruction = iterator.next();
                    if (instruction instanceof FieldInsnNode) {
                        FieldInsnNode fieldInsnNode = (FieldInsnNode) instruction;
                        String reference = fieldInsnNode.owner + "." + fieldInsnNode.name + "." + fieldInsnNode.desc;
                        Pair<String, FieldWrapper> pair = inlineFields.get(reference);
                        if (pair != null) {
                            int opcode = instruction.getOpcode();
                            FieldWrapper inlinedField = pair.getSecond();
                            MethodInsnNode injectedNode = null;
                            if (opcode == GETSTATIC) {
                                iterator.remove();
                                injectedNode = new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_field_" + reference, "()" + fieldInsnNode.desc, false);
                            } else if (opcode == PUTSTATIC) {
//                                if (Objects.equals("<clinit>", methodWrapper.getName()) && Objects.equals(classWrapper.getOriginalName(), inlinedField.getOwner().getOriginalName()) && !internalMatch(inlinedField)) {
//                                    WARN(TRANSLATION("phantom-shield-x.native.inline-static-field-warn"), inlinedField.getOwner().getOriginalName() + "." + inlinedField.getOriginalName() + "." + inlinedField.getDescription());
//                                }
                                iterator.remove();
                                injectedNode = new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_field_" + reference, "(" + fieldInsnNode.desc + ")V", false);
                            } else if (opcode == GETFIELD) {
                                iterator.remove();
                                injectedNode = new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_field_" + reference, "(Ljava/lang/Object;)" + fieldInsnNode.desc, false);
                            } else if (opcode == PUTFIELD) {
                                iterator.remove();
                                injectedNode = new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_field_" + reference, "(Ljava/lang/Object;" + fieldInsnNode.desc + ")V", false);
                            }

                            if (injectedNode != null) {
                                if (obfuscated) {
                                    iterator.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_init_" + fieldInsnNode.owner, "()V", false));
                                    iterator.add(injectedNode);
                                } else {
                                    MethodNode inlineMethod = new MethodNode();
                                    inlineMethod.access = ACC_PUBLIC | ACC_STATIC;
                                    inlineMethod.name = String.valueOf(inlineIndex.getAndIncrement());
                                    inlineMethod.desc = injectedNode.desc;
                                    inlineMethod.instructions.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_init_" + fieldInsnNode.owner, "()V", false));
                                    Type[] arguments = Type.getArgumentTypes(injectedNode.desc);
                                    for (int i = 0; i < arguments.length; i++) {
                                        Type argument = arguments[i];
                                        inlineMethod.instructions.add(new VarInsnNode(ASMUtils.getVarOpcode(argument, false), i));
                                    }
                                    inlineMethod.instructions.add(injectedNode);
                                    inlineMethod.instructions.add(new InsnNode(ASMUtils.getReturnOpcode(Type.getReturnType(injectedNode.desc))));
                                    inline.addMethod(inlineMethod);
                                    iterator.add(new MethodInsnNode(INVOKESTATIC, inline.getOriginalName(), inlineMethod.name, inlineMethod.desc));
                                }
                            }
                        }

                    } else if (instruction instanceof MethodInsnNode) {
                        MethodInsnNode methodInsnNode = (MethodInsnNode) instruction;
                        String reference = methodInsnNode.owner + "." + methodInsnNode.name + methodInsnNode.desc;
                        Pair<String, MethodWrapper> pair = inlineMethods.get(reference);

                        if (pair != null) {
                            int opcode = instruction.getOpcode();
                            MethodInsnNode injectedNode = null;
                            if (opcode == INVOKESTATIC) {
                                iterator.remove();
//                                StringBuilder descBuilder = new StringBuilder(methodInsnNode.desc);
//                                descBuilder.insert(1, "Ljava/lang/Class;");

                                Type returnType = Type.getReturnType(methodInsnNode.desc);
                                List<Type> arguments = new ArrayList<>(Arrays.asList(Type.getArgumentTypes(methodInsnNode.desc)));
                                arguments.add(Type.getType("Ljava/lang/Class;"));
                                String modifiedDesc = Type.getMethodDescriptor(returnType, arguments.toArray(new Type[0]));
                                iterator.add(new LdcInsnNode(Type.getObjectType(methodInsnNode.owner)));
                                injectedNode = new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_method_" + reference, modifiedDesc, false);
                            } else if (opcode == INVOKEVIRTUAL) {
                                iterator.remove();
                                StringBuilder descBuilder = new StringBuilder(methodInsnNode.desc);
                                descBuilder.insert(1, "Ljava/lang/Object;");
                                injectedNode = new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_method_-" + reference, descBuilder.toString(), false);
                            } else if (opcode == INVOKESPECIAL) {
                                ERROR(TRANSLATION("phantom-shield-x.native.inline-method-error1"));
                                System.exit(0);
                                return;
                            } else if (opcode == INVOKEINTERFACE) {
                                ERROR(TRANSLATION("phantom-shield-x.native.inline-method-error2"));
                                System.exit(0);
                                return;
                            }

                            if (injectedNode != null) {
                                if (obfuscated) {
                                    iterator.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_init_" + methodInsnNode.owner, "()V", false));
                                    iterator.add(injectedNode);
                                } else {
                                    String originalDesc = injectedNode.desc;
                                    String genericDesc = ASMUtils.getGenericMethodDesc(originalDesc);
                                    Type returnType = Type.getReturnType(originalDesc);

                                    MethodNode inlineMethod = new MethodNode();
                                    inlineMethod.access = ACC_PUBLIC | ACC_STATIC;
                                    inlineMethod.name = String.valueOf(inlineIndex.getAndIncrement());
                                    inlineMethod.desc = genericDesc;
                                    inlineMethod.instructions.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_init_" + methodInsnNode.owner, "()V", false));
                                    Type[] arguments = Type.getArgumentTypes(genericDesc);
                                    for (int i = 0; i < arguments.length; i++) {
                                        Type argument = arguments[i];
                                        inlineMethod.instructions.add(new VarInsnNode(ASMUtils.getVarOpcode(argument, false), i));
                                    }
                                    inlineMethod.instructions.add(injectedNode);
                                    inlineMethod.instructions.add(new InsnNode(ASMUtils.getReturnOpcode(returnType)));
                                    inline.addMethod(inlineMethod);
                                    iterator.add(new MethodInsnNode(INVOKESTATIC, inline.getOriginalName(), inlineMethod.name, inlineMethod.desc));
                                    if (returnType.getSort() == Type.ARRAY || returnType.getSort() == Type.OBJECT) {
                                        iterator.add(new TypeInsnNode(CHECKCAST, returnType.getInternalName()));
                                    }
                                }
                            }
                        } else {
                            switch (reference) {
                                case "tech/skidonion/obfuscator/inline/Inline.trycatch()V": {
                                    if (!obfuscated) {
                                        ERROR(TRANSLATION("phantom-shield-x.native.trycatch"));
                                        System.exit(0);
                                        return;
                                    }
                                    break;
                                }
                                case "tech/skidonion/obfuscator/inline/Inline._advanced_checkProtection(I)I":
                                case "tech/skidonion/obfuscator/inline/Inline._advanced_checkCRCImage(I)I":
                                case "tech/skidonion/obfuscator/inline/Inline._advanced_checkIsVirtualPC(I)I":
                                case "tech/skidonion/obfuscator/inline/Inline._advanced_checkIsDebuggerPresent(I)I": {
                                    if (obfuscated) break;
                                    MethodNode inlineMethod = new MethodNode();
                                    inlineMethod.access = ACC_PUBLIC | ACC_STATIC;
                                    inlineMethod.name = String.valueOf(inlineIndex.getAndIncrement());
                                    iterator.previous();
                                    AbstractInsnNode previous = iterator.previous();
                                    int constant;
                                    try {
                                        constant = ASMUtils.getIntegerFromInsn(previous);
                                    } catch (Exception exception) {
                                        throw new RuntimeException("Advanced Inline Method need a const argument...");
                                    }
                                    iterator.remove();
                                    iterator.next();
                                    inlineMethod.desc = "()I";
                                    inlineMethod.instructions.add(new LdcInsnNode(constant));
                                    inlineMethod.instructions.add(new MethodInsnNode(INVOKESTATIC, methodInsnNode.owner, methodInsnNode.name, methodInsnNode.desc, false));
                                    inlineMethod.instructions.add(new InsnNode(IRETURN));
                                    iterator.remove();
                                    inline.addMethod(inlineMethod);
                                    iterator.add(new MethodInsnNode(INVOKESTATIC, inline.getOriginalName(), inlineMethod.name, inlineMethod.desc));
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.verificationServer()Ljava/lang/String;": {
                                    iterator.remove();
                                    iterator.add(new LdcInsnNode(this.verification_server.getValue()));
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.publicKey()[B": {
                                    iterator.remove();
                                    for (AbstractInsnNode abstractInsnNode : ASMUtils.getByteArrayInst(verifyPublicKey)) {
                                        iterator.add(abstractInsnNode);
                                    }
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.shouldCheckHwid()Z": {
                                    iterator.remove();
                                    iterator.add(new InsnNode(verifyShouldCheckHwid ? ICONST_1 : ICONST_0));
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.shouldKeepAlive()Z": {
                                    iterator.remove();
                                    iterator.add(new InsnNode(verification_keep_alive.isEnable() ? ICONST_1 : ICONST_0));
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.sessionKey()[B": {
                                    iterator.remove();
                                    for (AbstractInsnNode abstractInsnNode : ASMUtils.getByteArrayInst(sessionKey)) {
                                        iterator.add(abstractInsnNode);
                                    }
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.nonce()[B": {
                                    iterator.remove();

                                    for (AbstractInsnNode abstractInsnNode : ASMUtils.getByteArrayInst(nonce)) {
                                        iterator.add(abstractInsnNode);
                                    }
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.softwareId()J": {
                                    iterator.remove();
                                    iterator.add(new LdcInsnNode(verifySoftwareId));
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.version()Ljava/lang/String;": {
                                    iterator.remove();
                                    iterator.add(new LdcInsnNode(verifyVersion));
                                    break;
                                }
                                case "tech/skidonion/verification/utils/Internals.decryptClasses(I[B)V": {
                                    iterator.remove();
                                    int locals = ASMUtils.computeMaxLocals(methodWrapper.getMethodNode());
                                    int hashIndex = locals++; // istore 1
                                    int keyIndex = locals++; // astore 2
                                    int srcIndex = locals++; // astore 3
                                    int dstIndex = locals++; // astore 4
                                    int cryptoIndex = locals; // astore 5
                                    iterator.add(new VarInsnNode(ASTORE, keyIndex)); // astore 2
                                    iterator.add(new VarInsnNode(ISTORE, hashIndex)); // istore 1
                                    iterator.add(new TypeInsnNode(NEW, "tech/skidonion/verification/crypto/ChaCha20"));
                                    iterator.add(new InsnNode(DUP));
                                    iterator.add(new VarInsnNode(ALOAD, keyIndex));
//                                    iterator.add(new MethodInsnNode(INVOKESTATIC, "tech/skidonion/verification/utils/Internals", "nonce", "()[B", false));
                                    for (AbstractInsnNode abstractInsnNode : ASMUtils.getByteArrayInst(nonce)) {
                                        iterator.add(abstractInsnNode);
                                    }

                                    iterator.add(new IntInsnNode(SIPUSH, 4096));
                                    iterator.add(new MethodInsnNode(INVOKESPECIAL, "tech/skidonion/verification/crypto/ChaCha20", "<init>", "([B[BI)V", false));
                                    iterator.add(new VarInsnNode(ASTORE, cryptoIndex));
                                    iterator.add(new VarInsnNode(ILOAD, hashIndex));
                                    LabelNode defaultLabel = new LabelNode();
                                    Set<String> roles = encryptedClasses.keySet();
                                    int[] hashes = new int[roles.size()];
                                    LabelNode[] labels = new LabelNode[roles.size()];
                                    int i;
                                    i = 0;
                                    for (String s : roles) {
                                        hashes[i] = s.hashCode();
                                        labels[i++] = new LabelNode();
                                    }
                                    iterator.add(new LookupSwitchInsnNode(defaultLabel, hashes, labels));

                                    i = 0;
                                    for (String roleName : roles) {
                                        iterator.add(labels[i]);
                                        if (verificationBuffer.containsKey(roleName)) {
                                            iterator.add(new VarInsnNode(ALOAD, keyIndex));
                                            iterator.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_decryptBuffer_" + roleName, "([B)V", false));
                                        }
                                        for (PriorityObject<ClassWrapper> cw : encryptedClasses.get(roleName).getSecond()) {
                                            iterator.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_encrypt_" + cw.getObject().getName(), "()[B", false));
                                            iterator.add(new VarInsnNode(ASTORE, srcIndex));
                                            iterator.add(new VarInsnNode(ALOAD, srcIndex));
                                            iterator.add(new InsnNode(ARRAYLENGTH));
                                            iterator.add(new IntInsnNode(NEWARRAY, T_BYTE));
                                            iterator.add(new VarInsnNode(ASTORE, dstIndex));
                                            iterator.add(new VarInsnNode(ALOAD, cryptoIndex));
                                            iterator.add(new VarInsnNode(ALOAD, dstIndex));
                                            iterator.add(new VarInsnNode(ALOAD, srcIndex));
                                            iterator.add(new VarInsnNode(ALOAD, srcIndex));
                                            iterator.add(new InsnNode(ARRAYLENGTH));
                                            iterator.add(new MethodInsnNode(INVOKEVIRTUAL, "tech/skidonion/verification/crypto/ChaCha20", "decrypt", "([B[BI)V", false));
                                            iterator.add(new VarInsnNode(ALOAD, dstIndex));
                                            iterator.add(new VarInsnNode(ALOAD, dstIndex));
                                            iterator.add(new InsnNode(ARRAYLENGTH));
                                            iterator.add(new MethodInsnNode(INVOKESTATIC, INLINE_DECLARE, "_defineClass_" + cw.getObject().getName(), "([BI)V"));
                                        }
                                        iterator.add(new JumpInsnNode(GOTO, defaultLabel));
                                        i++;
                                    }
                                    iterator.add(defaultLabel);
                                    break;
                                }
                                case "tech/skidonion/obfuscator/inline/Wrapper._debug_addDefaultCloudConstant(Ljava/lang/String;Ljava/lang/String;)V": {
                                    ERROR(TRANSLATION("phantom-shield-x.native.you"));
                                    System.exit(0);
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        });

        // join classpath
        if (!inline.getMethods().isEmpty()) {
            obfuscator.classes.put(inline.getName(), inline);
            obfuscator.classpath.put(inline.getName(), inline);
            injected.add(inline);
        }

        // remap for injected classes
        if (!injected.isEmpty()) {
            Collections.shuffle(injected);
            Renamer renamer = (Renamer) obfuscator.getRegister().get("renamer");
            Mapper mapper = new Mapper(obfuscator, injected, Collections.singleton(dummyInlineClassWrapper));
            mapper.setRepackage(true);
            mapper.setPrefixName(renamer.prefix_name.getValue());
            mapper.setRepakageName(loader_package.getValue());
            mapper.generateMappings();
            mapper.apply();
        }
    }

    @Override
    public void preprocess() throws Exception {
        this.init();

        // inject loader

        String loaderClassName = nativeDir + "/___";

        ClassNode loaderClass;

        List<ClassNode> classNodes = ASMUtils.readClassesWithInputStream("/binaries/phantomshield-loader.bin", 0);
        if (classNodes.size() != 1) throw new RuntimeException("impossible loader class member size");

        loaderClass = classNodes.get(0);
        loaderClass.sourceFile = "synthetic";

        ClassNode resultLoaderClass = new ClassNode();
        String originalLoaderClassName = loaderClass.name;
        loaderClass.accept(new ClassRemapper(resultLoaderClass, new Remapper() {
            @Override
            public String map(String internalName) {
                return internalName.equals(originalLoaderClassName) ? loaderClassName : internalName;
            }
        }));
        injectClassesAsResource(Collections.singletonList(resultLoaderClass));
    }

    @Override
    public String annotation() {
        return Type.getDescriptor(tech.skidonion.obfuscator.annotations.NativeObfuscation.class);
    }

    public AtomicInteger getCachedCallSitesIndex() {
        return cachedCallSitesIndex;
    }

    public NodeCache<String> getCachedInitClasses() {
        return cachedInitClasses;
    }

    public Snippets getSnippets() {
        return snippets;
    }

    public StringPool getStringPool() {
        return stringPool;
    }

    public NodeCache<String> getCachedStrings() {
        return cachedStrings;
    }

    public NodeCache<String> getCachedClasses() {
        return cachedClasses;
    }

    public NodeCache<CachedMethodInfo> getCachedMethods() {
        return cachedMethods;
    }

    public NodeCache<CachedFieldInfo> getCachedFields() {
        return cachedFields;
    }

    public String getNativeDir() {
        return nativeDir;
    }

    public HiddenMethodsPool getHiddenMethodsPool() {
        return hiddenMethodsPool;
    }

    public boolean isVerificationEnable() {
        return verification_enable.isEnable();
    }

    public boolean isUseInternalVerificationInterface() {
        return use_internal_user_interface.isEnable();
    }

    public Map<String, BufferContext> getVerificationBuffer() {
        return verificationBuffer;
    }

    public Map<String, Pair<byte[], List<PriorityObject<ClassWrapper>>>> getEncryptedClasses() {
        return encryptedClasses;
    }
}
