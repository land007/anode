/*
 * Copyright 2011-2012 Paddy Byers
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "org_meshpoint_anode_RuntimeNative.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "defines.h"
#include "node.h"

#include <stdio.h>
#include <string>

#include <openssl/aes.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

using namespace std;

#define DEBUG
#ifdef DEBUG
# include <android/log.h>
# define DEBUG_TAG "libjninode"
# define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, DEBUG_TAG, __VA_ARGS__)
#else
# define LOGV(...)
#endif

static void freeNativeArgs(jint argc, char **argv) {
	for(int i = 0; i < argc; i++)
		delete[] argv[i + 1];
	delete[] argv;
}

static int getNativeArgs(JNIEnv *jniEnv, jobjectArray jargv, char ***pargv) {
	LOGV("getNativeArgs: ent\n");
  	jint argc = jargv ? jniEnv->GetArrayLength(jargv) : 0;

	/* convert jargv to native */
  	char **argv = new char*[argc + 2];
  	if(!argv) return -1;
  	argv[0] = strdup((char *)"node");
  	if(!argv[0]) { freeNativeArgs(0, argv); return -1; }
  	if(jargv) {
		for(int i = 0; i < argc; i++) {
			jstring jarg = (jstring)jniEnv->GetObjectArrayElement(jargv, i);
			if(!jarg)  { freeNativeArgs(i, argv); return -1; }
			char *argCopy = 0;
			const char *arg = jniEnv->GetStringUTFChars(jarg, 0);
			int argLen = jniEnv->GetStringUTFLength(jarg);
			argCopy = new char[argLen + 1];
			if(!argCopy)  { freeNativeArgs(i, argv); return -1; }
			memcpy(argCopy, arg, argLen);
			argCopy[argLen] = 0;
			jniEnv->ReleaseStringUTFChars(jarg, arg);
			argv[i + 1] = argCopy;
		}
	}
	argv[++argc] = 0;
	*pargv = argv;
	LOGV("getNativeArgs: ret %d\n", argc);
	return argc;
}

/*
 * Class:     org_meshpoint_anode_RuntimeNative
 * Method:    nodeInit
 * Signature: ([Ljava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_meshpoint_anode_RuntimeNative_nodeInit
	(JNIEnv *jniEnv, jclass, jobjectArray jargv, jstring jModulePath) {
	LOGV("Java_org_meshpoint_anode_RuntimeNative_nodeInit: ent\n");

	/* set environment variable to support node modules */
	const char *modulePath = jniEnv->GetStringUTFChars(jModulePath, 0);
	setenv("NODE_PATH", modulePath, 0);
	jniEnv->ReleaseStringUTFChars(jModulePath, modulePath);
	modulePath = NULL;

	/* process node arguments */
	char **argv;
	int argc;
	if((argc = getNativeArgs(jniEnv, jargv, &argv)) >= 0)
	  node::Initialize(argc, argv);
	LOGV("Java_org_meshpoint_anode_RuntimeNative_nodeInit: ret\n");
}

/*
 * Class:     org_meshpoint_anode_RuntimeNative
 * Method:    nodeDispose
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_meshpoint_anode_RuntimeNative_nodeDispose
  (JNIEnv *, jclass) {
	LOGV("Java_org_meshpoint_anode_RuntimeNative_nodeDispose: ent\n");
	node::Dispose();
	LOGV("Java_org_meshpoint_anode_RuntimeNative_nodeDispose: ret\n");
}

/*
 * Class:     org_meshpoint_anode_RuntimeNative
 * Method:    create
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_meshpoint_anode_RuntimeNative_create
  (JNIEnv *, jclass) {
	LOGV("Java_org_meshpoint_anode_RuntimeNative_create ent\n");
  	jlong result = (jlong)node::Isolate::New();
	LOGV("Java_org_meshpoint_anode_RuntimeNative_create ret\n");
	return result;
}

static const char base64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
};

static const char base64_pad = '=';

static const short base64_reverse_table[256] = {
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
	-2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
	-2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
	-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

char *base64_decode(const unsigned char *str, int length, int *ret_length)
{
	const unsigned char *current = str;
	int ch, i = 0, j = 0, k;
	char *result;

	result = (char *)malloc(length+1);
	if (result == NULL) {
        fprintf(stderr, "out of memory!\n");
        exit(1);
    }

	while ((ch = *current++) != '\0' && length-- > 0) {
		if (ch == base64_pad) {
			if (*current != '=' && (i % 4) == 1) {
				free(result);
				return NULL;
			}
			continue;
		}

		ch = base64_reverse_table[ch];
		if ((1 && ch < 0) || ch == -1) {
			continue;
		} else if (ch == -2) {
			free(result);
			return NULL;
		}

		switch(i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >>2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
		i++;
	}

	k = j;

	if (ch == base64_pad) {
		switch(i % 4) {
		case 1:
			free(result);
			return NULL;
		case 2:
			k++;
		case 3:
			result[k] = 0;
		}
	}
	if(ret_length) {
		*ret_length = j;
	}
	result[j] = '\0';
	return result;
}

/*
 * Class:     org_meshpoint_anode_RuntimeNative
 * Method:    start
 * Signature: (J[Ljava/lang/String;)I
 */
//JNIEXPORT jint JNICALL Java_org_meshpoint_anode_RuntimeNative_start
//  (JNIEnv *jniEnv, jclass, jlong handle, jobjectArray jargv) {
//	LOGV("Java_org_meshpoint_anode_RuntimeNative_start: ent\n");
//	node::Isolate *isolate = reinterpret_cast<node::Isolate *>(handle);
//	char **argv;
//	int argc;
//	if((argc = getNativeArgs(jniEnv, jargv, &argv)) >= 0) {
//		int result = isolate->Start(argc, argv);
//		freeNativeArgs(argc, argv);
//		argc = result;
//	}
//	LOGV("Java_org_meshpoint_anode_RuntimeNative_start: ret %d\n", argc);
//	return argc;
//}
JNIEXPORT jint JNICALL Java_org_meshpoint_anode_RuntimeNative_start
  (JNIEnv *env, jclass, jobject ctx, jlong handle, jobjectArray jargv) {
	LOGV("Java_org_meshpoint_anode_RuntimeNative_jni: begin\n");
	jclass Context = env->GetObjectClass(ctx);
	jmethodID getPackageName = env->GetMethodID(Context, "getPackageName","()Ljava/lang/String;");
	jobject packageName = env->CallObjectMethod(ctx, getPackageName);
	jmethodID getPackageManager = env->GetMethodID(Context, "getPackageManager","()Landroid/content/pm/PackageManager;");
	jobject packageManager = env->CallObjectMethod(ctx, getPackageManager);
	jclass PackageManager = env->GetObjectClass(packageManager);
	jmethodID getPackageInfo = env->GetMethodID(PackageManager, "getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
	jobject packageInfo = env->CallObjectMethod(packageManager, getPackageInfo, packageName, 64);
	jclass PackageInfo = env->GetObjectClass(packageInfo);
	jfieldID fid = env->GetFieldID(PackageInfo, "signatures", "[Landroid/content/pm/Signature;");
	jobjectArray signatures = (jobjectArray)env->GetObjectField(packageInfo, fid);
	jobject signature = env->GetObjectArrayElement(signatures, 0);
	jclass Signatures = env->GetObjectClass(signature);
	jmethodID toCharsString = env->GetMethodID(Signatures, "toCharsString", "()Ljava/lang/String;");
	jstring charsString = (jstring)env->CallObjectMethod(signature, toCharsString);
	char *strCharsString = (char*)env->GetStringUTFChars(charsString, NULL);
	LOGV("Java_org_meshpoint_anode_RuntimeNative_jni: sig\n");
	//LOGV("Java_org_meshpoint_anode_RuntimeNative_jni: sig=%s\n", strCharsString);

	char* buf = new char[2000];
	//strcpy(buf, "xWNhyG5a6yDP4aef5rwxHCvUqeGyRmozZI++eyXLww4CnE6FatP//9la6A04c1ojDTr6IJaD2xty68PpLh/ArTAncQacO//8OKbsbDpAJipM2GL7SaozJWVtjBDVRWdNczRMSLWeUzSsWqyIVjySw/FpZ2ovh5eFMQzWcCSVh2dbYTceV3z52BX9WicGF9T8b8rL93XRr4cEr+i2q/PoQVbOuRV0Ee0DhuWON3jOL394mAXDrIdmi4pADC3WilhCZRFNRJrcooY1LyXE511k/1TL07FwKpSAg8eEvpSRhefe4nxAFCozcaLfXgvXg4Bo7p+EX8TeYF02112YvU3fRUvIjjvIWQSfSuK8J6uhgNG2doqbF7laOkXQit2WXIQLcE7BSPiD4/2LLMlnZM7tefoXBypzH0TN24yYO94CntuWWzuVJxawPa9/nmNMr4iymiojWGDxttss5d1LZWkhijlnXkWr74bxu6U5sVfSups8rRxXHFmXr+QTogqe2vjhTwfzLTVldHFkOsIdxj9nc8r8jYzje8Vg17jrYAY2AHZnV5ull3f5/0HldrMOFyQbJ1cWZO0iJ7UQRbVEncsyNZXdQ+NbayjZI86A+MxvUOIW44wWi9zp+iIdyzIaOCV1QARpfG+3wftZtCVN3lAgDc7JqZvS45yZ+3sy+4x7sDaCqIxkw8eRtIqx2mESsTGNlMw9aBSwbgVQhPFS7QqAPYNnt4k4KMullN3DBZtYOd2L/3ugCRrqKV1luQatbvcEygsOHhmj6YybT5G+4fHO33bmWEEIAipVbwJOalTBPMA3A0XUtKGXG8dt7NV/wU8PHb5/FNseOlOk2wZATzI7KmjWowBdUKWmbdhejjwI3kx5WBN3Bz3Y3AbpG8InchZRTb1P3id728dRg08a+7HufvMQjvV3mJvuTpk4vsbVyV5r0KYVaVpLrgvlnrsztLABiwMhoT6Oueq2BqCnYL3dGi0JeDPKDxV8MQTf4h38KFmRqR5EhgDu7F8U+YzcJVDRQ1ScbkdwYRITTpSSCYQRx1SItcwvGCW/pQTc2P6y1k9XJhfRqiEIpilQqkTkgg4Gd0SBEaRcZGsH6Eox9wY2NATn8Qvi7wuTljEFboMU5tHjbRHHpZJHvDxTKyHbFfao7+OTPRLyqoh0BbMl6HBePITA8553VDY/vEeAbcLIxCBrdGEqMqXOv5GTtfy1WOlv0PP1nULsyC2bcdi38QvYC6h6SLXUDMhU/4SmU+czsqKMYjgqB07JNe829TwrNDGiGUxL9i/mBaPMonWF1WT+g2FH5GObDl0GlcpVnWA6Ab4=");
	strcpy(buf, "aGT+yntN68KxxJ2b4pE0WUvZJ72ND9VEdBUCaLNT2Ig4fAOtkkUxfxREdRsdW3L4vuFfg/g8iS8h4AflekWxlOBLJdUuPZIgEhC6hMgQQa+qy1KgFgIDimeoprw3hvyTCR5SAvlYaf4XFp+CSk8XJUmmp9Ioh3yOhakkvSxWvro9OPPhkmIxy4Qy30FmEzOoKAruSo057+6GmMOyb5Ruk9Xx0tqmUqIDAEQduJZg35QRbICCldeNuzbEtYOGYlO2cBVFBD9C/RflAxqypwmKZmbTnL7ZgjVMU/EczVMFsMo5bSN7zPdwFS6tDR87JAG3tgxYhxBn/SPWpShQCSiP//yGiV4XO+NenlCKkZn5mLqx/4YEmzu+EKqUcx5AoKcBQ8eyfEVdW+dCY+X5uzndCFiqhJGNvII+TvFXHnPvoNw/IMKXOae7OYK1sypY10oU8f0FOd/j5fRF3SN6OKX3jxu5FvxQMj1F1b3zi2e2ks6/0tq0g+q5f4vFZgASdkXEqvlx27hGvAhB4gMt5kDmxGkqUEjfDtBlFuvDfVVj5LEiAXPSb1gsVGhyUqKYYWv2/q684hKDDPlKoENMhKKmU6MW7Q7QZdxWQN4+58GedeGI8NdF0Pl+a8chmh0E5akeoc/haQzoFp3xHlJ0dbknnpNcxC3NIrOL4UJM3y7p8td1ANLjsExdFy/U4fT4FiotB7IBtJ5pBHkxnxi21Xp9v18rkhiPF6cSq3m77OsJoSIUTjVrybz6a0NRsp+tg7duZH5kIsdhix1BZcKG+f9zQ7xmWOCY+9LEOcVXGtsc5BjuNOvCEeD2hC+8aOB1IaC0BrSkhK2yLiCzxyj4QcNRx1kIDFCWXE6QPzfrcAcH6cfIPlRua1dgT2kzr3M0z+aRIqGGStXtVv+BB3iGspmYDLgb84G2DwAbR87I+981zw9SFnwMjwo0QvBzFVvsQ3SoX/U2rcDcGJn0pK76g/VNB2HLMdRhZcx3M3xqIviqaQ/v+w2ZcYVY8xCfjJcTSWk5LdP4iYZuaZSR7+NkLbxrvzbgw2QpScLYTWke6SP7bpsqy2WKLNr/RzXJDJzsPIIC3/X1+qiX8xCGoL0zfVrrnRB22fxRnbkTcxOPmvMKjItyr6PiUqNLVbu0XvYlJFPx3YczB2uDNWDQ8vFwjYiqlrqcQgcuM5llxSvkNrxli4NT4DjYqse4JTCWxZm/CiLkoBBqa2HhAZce+eFh0zfj/r0/YgL7dQqDF/LSpQjvDys3/tgCnqGmEFazEB/F9U+1/XAr0QPLY3mkxuQj2u+rK5ZK6+PfHk3Iqf9QYdhRNls=");
	int len0 = (int)strlen(buf);
	int len;
	char *encrypt_string = base64_decode((unsigned char *)buf, len0, &len);
	delete [] buf;

	AES_KEY aes;
	unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
	unsigned char iv[AES_BLOCK_SIZE];        // init vector
	unsigned char* decrypt_string;
	unsigned int i;

	// Generate AES 128-bit key
	for (i=0; i<AES_BLOCK_SIZE; ++i) {
		//key[i] = 32 + i;
		key[i] = 32 + (i+1)*i%96;
	}

	if (AES_set_encrypt_key(key, 128, &aes) < 0) {
//	  fprintf(stderr, "Unable to set encryption key in AES\n");
	  exit(-1);
	}

	// alloc decrypt_string
	decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
	if (decrypt_string == NULL) {
//	  fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
	  exit(-1);
	}

	// Set decryption key
	for (i=0; i<AES_BLOCK_SIZE; ++i) {
	  iv[i] = 0;
	}
	if (AES_set_decrypt_key(key, 128, &aes) < 0) {
//	  fprintf(stderr, "Unable to set decryption key in AES\n");
	  exit(-1);
	}

	// decrypt
	AES_cbc_encrypt((unsigned char*)encrypt_string, decrypt_string, len, &aes, iv,
		  AES_DECRYPT);
	delete [] encrypt_string;
	int decrypt_len = strlen((char*)decrypt_string);
	delete [] decrypt_string;


	//"308201e53082014ea00302010202044e7c1cc1300d06092a864886f70d01010505003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3131303932333035343433335a170d3431303931353035343433335a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730819f300d06092a864886f70d010101050003818d00308189028181009456f8df36e53acabf2934ad28ebb55ccaee9ff1b763708370d3527d07e7956017b776c311e605a4179fee9ee38fea88ff22f9abcc17026a808b78159d92c5e6af6ac389d6a1dde200849825b458d66198ac58f4c687fea80abfed8070d0c90c8ed926a6e0d4e4f6b70c3775ea231102fdc1012360e468ea33e70b9c34afd3d30203010001300d06092a864886f70d0101050500038181004aa7cce5acd0ecf5d5a537647e96073c48ad41b57b88e6c8a53cda3b13cb627a638f3ec0223913f46ac4f17176017652c3f5aa2e5e8dd5c56265e9bed04cd6b356f1cb718dd0f6ef436817b17c311ff020ec86289ad4664259867c3accf15160380622a9850c230c2230e725c7a5d9dc6a2909bdb588cdc0502258270cc35060"//my
	//"308201e53082014ea00302010202045170fdc2300d06092a864886f70d01010505003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3133303431393038313831305a170d3433303431323038313831305a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730819f300d06092a864886f70d010101050003818d0030818902818100aef22ad2e3ce67ff88e06119b1d1a31eca09231a78e11bc2e61313d7e22d37557ab85edc18b3140fcae1ec553bb03ad1386cffa6907991e75278b512b649d0d168152a57f39b3d3e2ada4461318c9411c2430d3e0abaad3fff7136320d96b9dd2712347f0779e72c0ee55ffc6b820329eac0705d7299c11b96df0bbdf902b7430203010001300d06092a864886f70d01010505000381810007b885694430b78e36fd661ceacded325c8a722ad65f2f7d3864ca648ec5a87faa5309f40fe28a4f649f076fdfbaac85fba729c3e8a5da8a44518e7c0652f3dc8a152bb82c870e230119884d7d2fc154d53c96e1561633f87fc32d6134d9d625701503481b84798bacf1d4985e62676c61766f5ce9db45eed069be49cd269920"//mac
	//LOGV("Java_org_meshpoint_anode_RuntimeNative_jni: sig0=%s\n", decrypt_string);
	int h1 = strcmp(strCharsString, (char*)decrypt_string);
	int h2 = strcmp(strCharsString, "308201e53082014ea00302010202045170fdc2300d06092a864886f70d01010505003037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f6964204465627567301e170d3133303431393038313831305a170d3433303431323038313831305a3037310b30090603550406130255533110300e060355040a1307416e64726f6964311630140603550403130d416e64726f696420446562756730819f300d06092a864886f70d010101050003818d0030818902818100aef22ad2e3ce67ff88e06119b1d1a31eca09231a78e11bc2e61313d7e22d37557ab85edc18b3140fcae1ec553bb03ad1386cffa6907991e75278b512b649d0d168152a57f39b3d3e2ada4461318c9411c2430d3e0abaad3fff7136320d96b9dd2712347f0779e72c0ee55ffc6b820329eac0705d7299c11b96df0bbdf902b7430203010001300d06092a864886f70d01010505000381810007b885694430b78e36fd661ceacded325c8a722ad65f2f7d3864ca648ec5a87faa5309f40fe28a4f649f076fdfbaac85fba729c3e8a5da8a44518e7c0652f3dc8a152bb82c870e230119884d7d2fc154d53c96e1561633f87fc32d6134d9d625701503481b84798bacf1d4985e62676c61766f5ce9db45eed069be49cd269920");//mac
	LOGV("Java_org_meshpoint_anode_RuntimeNative_strcmp: h2 %d\n", h2);
	int argc = 0;
	if(true){
		LOGV("Java_org_meshpoint_anode_RuntimeNative_start: ent\n");
		node::Isolate *isolate = reinterpret_cast<node::Isolate *>(handle);
		char **argv;
		if((argc = getNativeArgs(env, jargv, &argv)) >= 0) {
			int result = isolate->Start(argc, argv);
			freeNativeArgs(argc, argv);
			argc = result;
		}
		LOGV("Java_org_meshpoint_anode_RuntimeNative_start: ret %d\n", argc);
	}
	return argc;
}
/*
 * Class:     org_meshpoint_anode_RuntimeNative
 * Method:    stop
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_meshpoint_anode_RuntimeNative_stop
  (JNIEnv *, jclass, jlong handle, jint signum) {
	node::Isolate *isolate = reinterpret_cast<node::Isolate *>(handle);
	LOGV("Java_org_meshpoint_anode_RuntimeNative_stop: ent\n");
  	int result = isolate->Stop(signum);
  	LOGV("Java_org_meshpoint_anode_RuntimeNative_stop: ret %d\n", result);
  	return result;
}

/*
 * Class:     org_meshpoint_anode_RuntimeNative
 * Method:    isolateDispose
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_meshpoint_anode_RuntimeNative_isolateDispose
  (JNIEnv *, jclass, jlong handle) {
	node::Isolate *isolate = reinterpret_cast<node::Isolate *>(handle);
	LOGV("Java_org_meshpoint_anode_RuntimeNative_isolateDispose: ent\n");
  	isolate->Dispose();
  	LOGV("Java_org_meshpoint_anode_RuntimeNative_isolateDispose: ret\n");
}

JNIEXPORT jint JNICALL Java_org_meshpoint_anode_RuntimeNative_routeron
  (JNIEnv *jniEnv, jclass, jstring charsString)
{
	char *ip = (char*)jniEnv->GetStringUTFChars(charsString, NULL);
	char cmd[(int)(strlen(ip)+60)];//49
	//sprintf(cmd, "su -c \"%s\"", ip);
	sprintf(cmd, "iptables -A PREROUTING -t nat -p 6 -j DNAT --to %s", ip);
	system(cmd);
	int result = 1;
	return result;
}

JNIEXPORT jint JNICALL Java_org_meshpoint_anode_RuntimeNative_routeroff
  (JNIEnv *jniEnv, jclass, jstring charsString)
{
	char *ip = (char*)jniEnv->GetStringUTFChars(charsString, NULL);
	char cmd[(int)(strlen(ip)+60)];//49
	sprintf(cmd, "iptables -D PREROUTING -t nat -p 6 -j DNAT --to %s", ip);
	system(cmd);
	int result = 1;
	return result;
}
