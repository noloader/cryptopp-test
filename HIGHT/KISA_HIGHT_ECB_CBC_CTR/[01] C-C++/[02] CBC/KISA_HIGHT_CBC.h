/**
@file KISA_HIGHT_CBC.h
@brief HIGHT CBC 암호 알고리즘
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/

#ifndef HIGHT_CBC_H
#define HIGHT_CBC_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef OUT
#define OUT
#endif

#ifndef IN
#define IN
#endif

#ifndef INOUT
#define INOUT
#endif

typedef unsigned int        DWORD;
typedef unsigned short      WORD;
typedef unsigned char       BYTE;

#ifndef _KISA_ENC_DEC_
#define _KISA_ENC_DEC_
typedef enum _KISA_ENC_DEC
{
	KISA_DECRYPT,
	KISA_ENCRYPT,
}KISA_ENC_DEC;
#endif

#ifndef _KISA_HIGHT_KEY_
#define _KISA_HIGHT_KEY_
typedef struct kisa_hight_key_st 
{
	BYTE key_data[128];
} KISA_HIGHT_KEY;
#endif

#ifndef _KISA_HIGHT_INFO_
#define _KISA_HIGHT_INFO_
typedef struct kisa_hight_info_st 
{	
	KISA_ENC_DEC	encrypt;				
	DWORD			ivec[4];				
	KISA_HIGHT_KEY	hight_key;				
	BYTE			userKey[16];
	DWORD			cbc_buffer[2];			
	int				buffer_length;			
	DWORD			cbc_last_block[2];		
} KISA_HIGHT_INFO;
#endif

/**
@brief BYTE 배열을 int 배열로 변환한다.
@param in :변환할 BYTE 포인터
@param inLen : 변환할 BYTE 배열 갯수
@return 인자로 받은 BYTE 배열의 int로 변환된 포인터를 반환한다. (내부적으로 malloc함으로 free를 꼭 해줘야 한다)
@remarks 전반적으로 동일한 기능의 함수가 SEED CTR, CBC, HIGHT CTR, CBC에 있으나 include 시 
동일 함수일 경우 충돌 때문에 뒤에 구분할 수 있도록 운영모드를 붙인다.
*/
DWORD* chartoint32_for_HIGHT_CBC( IN BYTE *in, IN int inLen );

/**
@brief int 배열을 BYTE 배열로 변환한다.
@param in :변환할 int 포인터
@param inLen : 변환할 int 배열 갯수
@return 인자로 받은 int 배열을 char로 변환한 포인터를 반환한다. (내부적으로 malloc함으로 free를 꼭 해줘야 한다)
@remarks 전반적으로 동일한 기능의 함수가 SEED CTR, CBC, HIGHT CTR, CBC에 있으나 include 시 
동일 함수일 경우 충돌 때문에 뒤에 구분할 수 있도록 운영모드를 붙인다.
*/
BYTE* int32tochar_for_HIGHT_CBC( IN DWORD *in, IN int inLen );

/**
@brief HIGHT CBC 알고리즘 초기화 함수
@param pInfo : CBC 내부에서 사용되는 구조체로써 유저가 변경하면 안된다.(메모리 할당되어 있어야 한다.)
@param enc : 암호화 및 복호화 모드 지정
@param pUserKey : 사용자가 지정하는 입력 키(16 BYTE)
@param pbIV : 사용자가 지정하는 초기화 벡터(16 BYTE)
@return 0: pInfo 또는 pUserKey 또는 pbIV 포인터가 NULL일 경우, 
        1: 성공
*/
int HIGHT_CBC_init( OUT KISA_HIGHT_INFO *pInfo, IN KISA_ENC_DEC enc, IN BYTE *pUserKey, IN BYTE *pbIV );

/**
@brief HIGHT CBC 다중 블럭 암호화/복호화 함수
@param pInfo : HIGHT_CBC_init 에서 설정된 KISA_HIGHT_INFO 구조체
@param in : 평문/암호문 ( 평문은 chartoint32_for_HIGHT_CBC를 사용하여 int로 변환된 데이터)
@param inLen : 평문/암호문 길이(BYTE 단위)
@param out : 평문/암호문 버퍼
@param outLen : 진행된 평문/암호문의 길이(BYTE 단위로 넘겨준다)
@return 0: inLen의 값이 0보다 작은 경우, KISA_HIGHT_INFO 구조체나 in, out에 널 포인터가 할당되었을 경우
        1: 성공
*/
int HIGHT_CBC_Process( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *in, IN int inLen, OUT DWORD *out, OUT int *outLen );

/**
@brief HIGHT CBC 운영모드 종료 및 패딩 처리(PKCS7)
@param pInfo : HIGHT_CBC_Process 를 거친 KISA_HIGHT_INFO 구조체
@param out : 평문/암호문 출력 버퍼
@param outLen : 출력 버퍼에 저장된 데이터 길이(BYTE 단위의 평문길이)
@return 
- 0 :  inLen의 값이 0보다 작은 경우,
       KISA_HIGHT_INFO 구조체나 out에 널 포인터가 할당되었을 경우
- 1 :  성공
@remarks 패딩 로직때문에 16바이트 블럭으로 처리함으로 복호화 시 출력 버퍼는 
평문보다 16바이트 커야 한다.(평문이 16바이트 블럭 시 패딩 데이타가 16바이트가 들어간다.)
*/
int HIGHT_CBC_Close( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *out, IN int out_offset, IN int *outLen );

/**
@brief 처리하고자 하는 데이터가 적을 경우에 사용
@param pbszUserKey : 사용자가 지정하는 입력 키(16 BYTE)
@param pszbIV : 사용자가 지정하는 초기화 벡터(16 BYTE)
@param pbszPlainText : 사용자 입력 평문
@param nPlainTextLen : 평문 길이(BYTE 단위의 평문길이)
@param pbszCipherText : 암호문 출력 버퍼
@return 암호화가 진행된 길이(char 단위)
@remarks 패딩 로직때문에 16바이트 블럭으로 처리함으로 pbszCipherText는 평문보다 16바이트 커야 한다.
(평문이 16바이트 블럭 시 패딩 데이타가 16바이트가 들어간다.)
*/
int HIGHT_CBC_Encrypt( IN BYTE *pbszUserKey, IN BYTE *pbszIV, IN BYTE *pbszPlainText, IN int in_offset, IN int nPlainTextLen, OUT BYTE *pbszCipherText );

/**
@brief 처리하고자 하는 데이터가 적을 경우에 사용
@param pbszUserKey : 사용자가 지정하는 입력 키(16 BYTE)
@param pszbIV : 사용자가 지정하는 초기화 벡터(16 BYTE)
@param pbszCipherText : 암호문
@param nCipherTextLen : 암호문 길이(BYTE 단위의 평문길이)
@param pbszPlainText : 평문 출력 버퍼
@return 복호화가 진행된 길이(char 단위)
*/
int HIGHT_CBC_Decrypt( IN BYTE *pbszUserKey, IN BYTE *pbszIV, IN BYTE *pbszCipherText, IN int in_offset, IN int nCipherTextLen, OUT BYTE *result );

#ifdef  __cplusplus
}
#endif

#endif