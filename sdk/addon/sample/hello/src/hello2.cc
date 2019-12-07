#include <node.h>
#include <v8.h>

#include <stdio.h>
#include <string>
#include <stdlib.h>

#include <openssl/aes.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>

//#include <node_buffer.h>
//#include <zlib.h>

using namespace node;
using namespace v8;
using namespace std;

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


char* base64_encode(const unsigned char *str, int length, int *ret_length) /* {{{ */
{
	const unsigned char *current = str;
	char *p;
	char *result;

	if ((length + 2) < 0 || ((length + 2) / 3) >= (1 << (sizeof(int) * 8 - 2))) {
		if (ret_length != NULL) {
			*ret_length = 0;
		}
		return NULL;
	}

	result = (char *)malloc((((length + 2) / 3) * 4)*(sizeof(char))+(1));
	if (result == NULL) {
        fprintf(stderr, "out of memory!\n");
        exit(1);
    }
	p = result;

	while (length > 2) {
		*p++ = base64_table[current[0] >> 2];
		*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		*p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		*p++ = base64_table[current[2] & 0x3f];

		current += 3;
		length -= 3;
	}

	if (length != 0) {
		*p++ = base64_table[current[0] >> 2];
		if (length > 1) {
			*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			*p++ = base64_table[(current[1] & 0x0f) << 2];
			*p++ = base64_pad;
		} else {
			*p++ = base64_table[(current[0] & 0x03) << 4];
			*p++ = base64_pad;
			*p++ = base64_pad;
		}
	}
	if (ret_length != NULL) {
		*ret_length = (int)(p - result);
	}
	*p = '\0';
	return result;
}


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

Handle<Value> Method(const Arguments& args) {
  HandleScope scope;

    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char* input_string;
    unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;
 
    // check usage
//    if (argc != 2) {
//        fprintf(stderr, "%s <plain text>\n", argv[0]);
//        exit(-1);
//    }
    
//    char argv[2000];
//    strcat(argv, "1234");//可考虑
    
    Local<Value> code = args[0]->ToString();
    String::Utf8Value utf8_value(code);
    string rawStr = string(*utf8_value);
	char* argv = new char[rawStr.length()];
	memcpy(argv,rawStr.c_str(),rawStr.length());
//	printf("%s\n",argv);
    
//    unsigned char buf [1024] = {'\0'};
//    uLong bufLen = sizeof(buf);
//    int ret = compress(buf, &bufLen, (const Bytef*)(rawStr.c_str()), (uLong)rawStr.length());
//    if(ret != Z_OK){
//    	ThrowException(Exception::TypeError(String::New("destination memory too little"))); 
//        return scope.Close(Undefined()); 
//    }
//    Buffer *outBuf = Buffer::New ((const char*)buf, bufLen);
    
    // set the encryption length
    len = 0;
    if ((strlen(argv) + 1) % AES_BLOCK_SIZE == 0) {
        len = strlen(argv) + 1;
    } else {
        len = ((strlen(argv) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }
 
    // set the input string
    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char*)input_string, argv, strlen(argv));
 
    // Generate AES 128-bit key
    for (i=0; i<16; ++i) {
        key[i] = 32 + i;
    }
 
    // Set encryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }
 
    // alloc encrypt_string
    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));    
    if (encrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }
 
    // encrypt (iv will change)
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);
 
    // alloc decrypt_string
    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (decrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
        exit(-1);
    }
 
    // Set decryption key
    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }
 
    // decrypt
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv, 
            AES_DECRYPT);
 
    // print
    printf("input_string = %s\n", input_string);
    printf("encrypted string = ");
    for (i=0; i<len; ++i) {
        printf("%x%x", (encrypt_string[i] >> 4) & 0xf, 
                encrypt_string[i] & 0xf);    
    }
    printf("\n");
    printf("decrypted string = %s\n", decrypt_string);
    
    
//    string plainStr = "";
    int len1;
    char *str = base64_encode(encrypt_string,len,&len1);
    Local<String> content = String::New(str, len);
//    printf("%s\n",plainStr.c_str());
//    Local<String> content = String::New("world");
//    Local<String> content = String::New(argv);
//    Local<String> content = String::New(str);
    
    delete [] argv;
  return scope.Close(content);
}

void init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("hello"),
      FunctionTemplate::New(Method)->GetFunction());
}

NODE_MODULE(hello, init)
