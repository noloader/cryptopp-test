/**
@file KISA_HIGHT_CBC.h
@brief HIGHT CBC ��ȣ �˰���
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
@brief BYTE �迭�� int �迭�� ��ȯ�Ѵ�.
@param in :��ȯ�� BYTE ������
@param inLen : ��ȯ�� BYTE �迭 ����
@return ���ڷ� ���� BYTE �迭�� int�� ��ȯ�� �����͸� ��ȯ�Ѵ�. (���������� malloc������ free�� �� ����� �Ѵ�)
@remarks ���������� ������ ����� �Լ��� SEED CTR, CBC, HIGHT CTR, CBC�� ������ include �� 
���� �Լ��� ��� �浹 ������ �ڿ� ������ �� �ֵ��� ���带 ���δ�.
*/
DWORD* chartoint32_for_HIGHT_CBC( IN BYTE *in, IN int inLen );

/**
@brief int �迭�� BYTE �迭�� ��ȯ�Ѵ�.
@param in :��ȯ�� int ������
@param inLen : ��ȯ�� int �迭 ����
@return ���ڷ� ���� int �迭�� char�� ��ȯ�� �����͸� ��ȯ�Ѵ�. (���������� malloc������ free�� �� ����� �Ѵ�)
@remarks ���������� ������ ����� �Լ��� SEED CTR, CBC, HIGHT CTR, CBC�� ������ include �� 
���� �Լ��� ��� �浹 ������ �ڿ� ������ �� �ֵ��� ���带 ���δ�.
*/
BYTE* int32tochar_for_HIGHT_CBC( IN DWORD *in, IN int inLen );

/**
@brief HIGHT CBC �˰��� �ʱ�ȭ �Լ�
@param pInfo : CBC ���ο��� ���Ǵ� ����ü�ν� ������ �����ϸ� �ȵȴ�.(�޸� �Ҵ�Ǿ� �־�� �Ѵ�.)
@param enc : ��ȣȭ �� ��ȣȭ ��� ����
@param pUserKey : ����ڰ� �����ϴ� �Է� Ű(16 BYTE)
@param pbIV : ����ڰ� �����ϴ� �ʱ�ȭ ����(16 BYTE)
@return 0: pInfo �Ǵ� pUserKey �Ǵ� pbIV �����Ͱ� NULL�� ���, 
        1: ����
*/
int HIGHT_CBC_init( OUT KISA_HIGHT_INFO *pInfo, IN KISA_ENC_DEC enc, IN BYTE *pUserKey, IN BYTE *pbIV );

/**
@brief HIGHT CBC ���� �� ��ȣȭ/��ȣȭ �Լ�
@param pInfo : HIGHT_CBC_init ���� ������ KISA_HIGHT_INFO ����ü
@param in : ��/��ȣ�� ( ���� chartoint32_for_HIGHT_CBC�� ����Ͽ� int�� ��ȯ�� ������)
@param inLen : ��/��ȣ�� ����(BYTE ����)
@param out : ��/��ȣ�� ����
@param outLen : ����� ��/��ȣ���� ����(BYTE ������ �Ѱ��ش�)
@return 0: inLen�� ���� 0���� ���� ���, KISA_HIGHT_INFO ����ü�� in, out�� �� �����Ͱ� �Ҵ�Ǿ��� ���
        1: ����
*/
int HIGHT_CBC_Process( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *in, IN int inLen, OUT DWORD *out, OUT int *outLen );

/**
@brief HIGHT CBC ���� ���� �� �е� ó��(PKCS7)
@param pInfo : HIGHT_CBC_Process �� ��ģ KISA_HIGHT_INFO ����ü
@param out : ��/��ȣ�� ��� ����
@param outLen : ��� ���ۿ� ����� ������ ����(BYTE ������ �򹮱���)
@return 
- 0 :  inLen�� ���� 0���� ���� ���,
       KISA_HIGHT_INFO ����ü�� out�� �� �����Ͱ� �Ҵ�Ǿ��� ���
- 1 :  ����
@remarks �е� ���������� 16����Ʈ ������ ó�������� ��ȣȭ �� ��� ���۴� 
�򹮺��� 16����Ʈ Ŀ�� �Ѵ�.(���� 16����Ʈ �� �� �е� ����Ÿ�� 16����Ʈ�� ����.)
*/
int HIGHT_CBC_Close( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *out, IN int out_offset, IN int *outLen );

/**
@brief ó���ϰ��� �ϴ� �����Ͱ� ���� ��쿡 ���
@param pbszUserKey : ����ڰ� �����ϴ� �Է� Ű(16 BYTE)
@param pszbIV : ����ڰ� �����ϴ� �ʱ�ȭ ����(16 BYTE)
@param pbszPlainText : ����� �Է� ��
@param nPlainTextLen : �� ����(BYTE ������ �򹮱���)
@param pbszCipherText : ��ȣ�� ��� ����
@return ��ȣȭ�� ����� ����(char ����)
@remarks �е� ���������� 16����Ʈ ������ ó�������� pbszCipherText�� �򹮺��� 16����Ʈ Ŀ�� �Ѵ�.
(���� 16����Ʈ �� �� �е� ����Ÿ�� 16����Ʈ�� ����.)
*/
int HIGHT_CBC_Encrypt( IN BYTE *pbszUserKey, IN BYTE *pbszIV, IN BYTE *pbszPlainText, IN int in_offset, IN int nPlainTextLen, OUT BYTE *pbszCipherText );

/**
@brief ó���ϰ��� �ϴ� �����Ͱ� ���� ��쿡 ���
@param pbszUserKey : ����ڰ� �����ϴ� �Է� Ű(16 BYTE)
@param pszbIV : ����ڰ� �����ϴ� �ʱ�ȭ ����(16 BYTE)
@param pbszCipherText : ��ȣ��
@param nCipherTextLen : ��ȣ�� ����(BYTE ������ �򹮱���)
@param pbszPlainText : �� ��� ����
@return ��ȣȭ�� ����� ����(char ����)
*/
int HIGHT_CBC_Decrypt( IN BYTE *pbszUserKey, IN BYTE *pbszIV, IN BYTE *pbszCipherText, IN int in_offset, IN int nCipherTextLen, OUT BYTE *result );

#ifdef  __cplusplus
}
#endif

#endif