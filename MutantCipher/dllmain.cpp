// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <stdint.h>
#include "context_cipher.h"
#include "md5.h"

struct Cipher* cipher_data;

//Tamaño para representar decimalmente 2^32 posiciones: 10 digitos. Key size es un int (4bytes). (2^64 = 16 trillones (18 ceros), 24 bits para concat)
#define CONCAT_TAM 14
#define NOOP ((void)0)
#define ENABLE_PRINTS 1					// Affects the PRINT() functions. If 0 does not print anything. If 1 traces are printed.
#define PRINT(...) do { if (ENABLE_PRINTS) printf(__VA_ARGS__); else NOOP;} while (0)
#define PRINT1(...) PRINT("    "); PRINT(__VA_ARGS__)
#define PRINT2(...) PRINT("        "); PRINT(__VA_ARGS__)
#define PRINT3(...) PRINT("            "); PRINT(__VA_ARGS__)
#define PRINT4(...) PRINT("                "); PRINT(__VA_ARGS__)
#define PRINT5(...) PRINT("                    "); PRINT(__VA_ARGS__)
#define PRINTX(DEPTH, ...) do { if (ENABLE_PRINTS) { for (int x=0; x<DEPTH; x++){ printf("    ");} printf(__VA_ARGS__); } else NOOP;} while (0)
#define PRINT_HEX(BUF, BUF_SIZE) print_hex(#BUF, BUF, BUF_SIZE);

DWORD print_hex(char* buf_name, void* buf, int size) {
    if (ENABLE_PRINTS) {
        //printf("First %d bytes of %s contain:\n", size, buf_name);

        //byte [size*3 + size/32 + 1] str_fmt_buf;
        char* full_str = NULL;
        char* target_str = NULL;
        //int total = 0;

        // Size of string will consist on:
        //   (size*3)			 - 3 characters for every byte (2 hex characters plus 1 space). Space changed for '\n' every 32 bytes
        //   (size/8 - size/32)	 - Every 8 bytes another space is added after the space (if it is not multiple of 32, which already has '\n' instead)
        //   (1)				 - A '\n' is added at the end
        full_str = calloc((size * 3) + (size / 8 - size / 32) + (1), sizeof(char));
        if (full_str == NULL) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        target_str = full_str;

        for (int i = 0; i < size; i++) {
            if ((i + 1) % 32 == 0) {
                target_str += sprintf(target_str, "%02hhX\n", ((byte*)buf)[i]);
            }
            else if ((i + 1) % 8 == 0) {
                target_str += sprintf(target_str, "%02hhX  ", ((byte*)buf)[i]);
            }
            else {
                target_str += sprintf(target_str, "%02hhX ", ((byte*)buf)[i]);
            }
        }
        target_str += sprintf(target_str, "\n");
        printf(full_str);
        free(full_str);
    }
    return ERROR_SUCCESS;
}

//Function prototypes
extern "C" _declspec(dllexport) int init(struct Cipher* cipher_data_param);
extern "C" _declspec(dllexport) int cipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key);
extern "C" _declspec(dllexport) int decipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key);

int init(struct Cipher* cipher_data_param) {
    cipher_data = cipher_data_param;
    printf("Initializing (%ws)\n", cipher_data->file_name);

    return 0;
}

int cipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key) {
    printf("Ciphering (%ws)\n", cipher_data->file_name);
    byte* result;
    char concat[CONCAT_TAM];
    int total = 0;
    DWORD pos_max = size + offset;
    
    for (int i = offset; i < pos_max; i++) {
        snprintf(concat, CONCAT_TAM, "%d%s", i, key->data);// Ahora mismo no hace padding con 0s
        result = md5String(concat);
        for (int j = 0; j < 16; j++) { 
            total += result[j];
        }
        total = (((int*)in_buf)[i] + total) % 256;
        ((char*)out_buf)[i] = (byte)total;
        free(result);
    }
    return 0;
}

int decipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, size_t offset, struct KeyData* key) {
    printf("Deciphering (%ws)\n", cipher_data->file_name);
    byte* result;
    char concat[CONCAT_TAM];
    int total = 0;
    DWORD pos_max = size + offset;

    for (int i = offset; i < pos_max; i++) {
        snprintf(concat, CONCAT_TAM, "%d%s", i, key->data);// Ahora mismo no hace padding con 0s
        result = md5String(concat);
        for (int j = 0; j < 16; j++) {
            total += result[j];
        }
        total = (((int*)in_buf)[i] + total) % 256;
        ((char*)out_buf)[i] = (byte)total;
        free(result);
    }
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

