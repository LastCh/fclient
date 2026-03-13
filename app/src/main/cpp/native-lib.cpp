#include <jni.h>
#include <string>
#include <android/log.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/android_sink.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/des.h>

#define LOG_INFO(...) __android_log_print(ANDROID_LOG_INFO, "fclient_ndk", __VA_ARGS__)
#define LOG_ERROR(...) __android_log_print(ANDROID_LOG_ERROR, "fclient_ndk", __VA_ARGS__)

#define SLOG_INFO(...) android_logger->info( __VA_ARGS__ )
#define SLOG_ERROR(...) android_logger->error( __VA_ARGS__ )


auto android_logger = spdlog::android_logger_mt("android", "fclient_ndk");

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
char *personalization = "fclient-sample-app";

JavaVM* gJvm = nullptr;

extern "C" JNIEXPORT jstring JNICALL
Java_ru_iu3_fclient_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    LOG_INFO("Hello from c++ %d", 2026);
    SLOG_INFO("Hello from spdlog {0}", 2026);
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_ru_iu3_fclient_MainActivity_LOGFromJNI(
        JNIEnv* env,
        jclass /* this */) {

    LOG_INFO("Lib Has been added c++ %d", 2026);
    SLOG_INFO("Lib Has been added spdlog {}", 2026);
}

extern "C" JNIEXPORT void JNICALL
Java_ru_iu3_fclient_MainActivity_LOGErrFromJNI(
        JNIEnv* env,
        jclass /* this */) {

    LOG_ERROR("Error c++ %d", 2026);
    SLOG_ERROR("Error spdlog {}", 2026);
}

extern "C" JNIEXPORT jint JNICALL
Java_ru_iu3_fclient_MainActivity_initRng(JNIEnv *env, jclass clazz) {
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    return mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                                  (const unsigned char *) personalization,
                                  strlen( personalization ) );
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_ru_iu3_fclient_MainActivity_randomBytes(JNIEnv *env, jclass, jint no) {
    uint8_t * buf = new uint8_t [no];
    mbedtls_ctr_drbg_random(&ctr_drbg, buf, no);
    jbyteArray rnd = env->NewByteArray(no);
    env->SetByteArrayRegion(rnd, 0, no, (jbyte *)buf);
    delete[] buf;
    return rnd;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_ru_iu3_fclient_MainActivity_encrypt(JNIEnv *env, jclass, jbyteArray key, jbyteArray data)
{
    jsize ksz = env->GetArrayLength(key);
    jsize dsz = env->GetArrayLength(data);
    if ((ksz != 16) || (dsz <= 0)) {
        return env->NewByteArray(0);
    }
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);

    jbyte * pkey = env->GetByteArrayElements(key, 0);

    // Паддинг PKCS#5
    int rst = dsz % 8;
    int sz = dsz + 8 - rst;
    int pad = 8 - (dsz % 8);
    if (pad == 0)
        pad = 8;
    uint8_t * buf = new uint8_t[sz];
    for (int i = 0; i < pad; i++)
        buf[dsz + i] = pad;
    jbyte * pdata = env->GetByteArrayElements(data, 0);
    std::copy(pdata, pdata + dsz, buf);
    mbedtls_des3_set2key_enc(&ctx, (uint8_t *)pkey);
    int cn = sz / 8;
    for (int i = 0; i < cn; i++)
        mbedtls_des3_crypt_ecb(&ctx, buf + i*8, buf + i*8);
    jbyteArray dout = env->NewByteArray(sz);
    env->SetByteArrayRegion(dout, 0, sz, (jbyte *)buf);
    delete[] buf;
    env->ReleaseByteArrayElements(key, pkey, 0);
    env->ReleaseByteArrayElements(data, pdata, 0);
    return dout;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_ru_iu3_fclient_MainActivity_decrypt(JNIEnv *env, jclass, jbyteArray key, jbyteArray data)
{
    jsize ksz = env->GetArrayLength(key);
    jsize dsz = env->GetArrayLength(data);
    if ((ksz != 16) || (dsz <= 0) || ((dsz % 8) != 0)) {
        return env->NewByteArray(0);
    }
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);

    jbyte * pkey = env->GetByteArrayElements(key, 0);

    uint8_t * buf = new uint8_t[dsz];

    jbyte * pdata = env->GetByteArrayElements(data, 0);
    std::copy(pdata, pdata + dsz, buf);
    mbedtls_des3_set2key_dec(&ctx, (uint8_t *)pkey);
    int cn = dsz / 8;
    for (int i = 0; i < cn; i++)
        mbedtls_des3_crypt_ecb(&ctx, buf + i*8, buf +i*8);

    //PKCS#5. упрощено. по соображениям безопасности надо проверить каждый байт паддинга
    int pad = buf[dsz - 1];
    int sz = dsz - pad;

    jbyteArray dout = env->NewByteArray(sz);
    env->SetByteArrayRegion(dout, 0, sz, (jbyte *)buf);
    delete[] buf;
    env->ReleaseByteArrayElements(key, pkey, 0);
    env->ReleaseByteArrayElements(data, pdata, 0);
    return dout;
}

JNIEXPORT jint JNICALL JNI_OnLoad (JavaVM* pjvm, void* reserved)
{
    gJvm = pjvm;
    return JNI_VERSION_1_6;
}

JNIEnv* getEnv (bool& detach)
{
    JNIEnv* env = nullptr;
    int status = gJvm->GetEnv ((void**)&env, JNI_VERSION_1_6);
    detach = false;
    if (status == JNI_EDETACHED)
    {
        status = gJvm->AttachCurrentThread (&env, NULL);
        if (status < 0)
        {
            return nullptr;
        }
        detach = true;
    }
    return env;
}

void releaseEnv (bool detach, JNIEnv* env)
{
    if (detach && (gJvm != nullptr))
    {
        gJvm->DetachCurrentThread ();
    }
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_ru_iu3_fclient_MainActivity_transaction(JNIEnv *xenv, jobject xthiz, jbyteArray xtrd) {
    jobject thiz = xenv->NewGlobalRef(xthiz);
    jbyteArray trd = (jbyteArray)xenv->NewGlobalRef(xtrd);

    std::thread t([thiz, trd]() {
        bool detach = false;
        JNIEnv* env = getEnv(detach);
        if (env == nullptr) {
            return;
        }

        jclass cls = env->GetObjectClass(thiz);
        if (cls == nullptr) {
            env->DeleteGlobalRef(thiz);
            env->DeleteGlobalRef(trd);
            releaseEnv(detach, env);
            return;
        }

        jmethodID enterPinId = env->GetMethodID(
                cls,
                "enterPin",
                "(ILjava/lang/String;)Ljava/lang/String;"
        );

        jmethodID resultId = env->GetMethodID(
                cls,
                "transactionResult",
                "(Z)V"
        );

        if (enterPinId == nullptr || resultId == nullptr) {
            env->DeleteGlobalRef(thiz);
            env->DeleteGlobalRef(trd);
            releaseEnv(detach, env);
            return;
        }

        jbyte* p = env->GetByteArrayElements(trd, 0);
        jsize sz = env->GetArrayLength(trd);

        if ((sz != 9) || ((uint8_t)p[0] != 0x9F) || ((uint8_t)p[1] != 0x02) || ((uint8_t)p[2] != 0x06)) {
            env->ReleaseByteArrayElements(trd, p, 0);
            env->CallVoidMethod(thiz, resultId, JNI_FALSE);
            env->DeleteGlobalRef(thiz);
            env->DeleteGlobalRef(trd);
            releaseEnv(detach, env);
            return;
        }

        char buf[13];
        for (int i = 0; i < 6; i++) {
            uint8_t n = (uint8_t)p[3 + i];
            buf[i * 2] = ((n & 0xF0) >> 4) + '0';
            buf[i * 2 + 1] = (n & 0x0F) + '0';
        }
        buf[12] = '\0';

        jstring jamount = env->NewStringUTF(buf);

        int ptc = 3;
        while (ptc > 0) {
            jstring jpin = (jstring)env->CallObjectMethod(thiz, enterPinId, ptc, jamount);

            if (jpin == nullptr) {
                ptc--;
                continue;
            }

            const char* utf = env->GetStringUTFChars(jpin, nullptr);
            bool ok = (utf != nullptr) && (strcmp(utf, "1234") == 0);

            if (utf != nullptr) {
                env->ReleaseStringUTFChars(jpin, utf);
            }

            env->DeleteLocalRef(jpin);

            if (ok) {
                break;
            }

            ptc--;
        }

        env->CallVoidMethod(thiz, resultId, (ptc > 0) ? JNI_TRUE : JNI_FALSE);

        env->DeleteLocalRef(jamount);
        env->ReleaseByteArrayElements(trd, p, 0);
        env->DeleteGlobalRef(thiz);
        env->DeleteGlobalRef(trd);
        releaseEnv(detach, env);
    });

    t.detach();
    return JNI_TRUE;
}


