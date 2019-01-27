/**
@file KISA_HIGHT_CTR.h
@brief HIGHT CTR ��ȣ �˰���
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/

#ifndef HIGHT_CTR_H
#define HIGHT_CTR_H

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
	DWORD			ctr[4];				
	KISA_HIGHT_KEY	hight_key;				
	BYTE			userKey[16];
	DWORD			cbc_buffer[2];			
	int				buffer_length;			
	DWORD			cbc_last_block[2];		
} KISA_HIGHT_INFO;
#endif

#ifndef _NONCE_TYPE_
#define _NONCE_TYPE_
typedef enum _NONCE_TYPE
{
	NONCE_NONE,
	NONCE_OR,
	NONCE_AND,
	NONCE_XOR,
}NONCE_TYPE;
#endif

/**
@brief HIGHT_CTR_init�� ����ϴ� �ʱⰪ(BYTE *pbszCounter)�� �����Ѵ�.
@param type : OR, AND, XOR ������ Ÿ�� ����
@param pbszIV : IV(�ʱ� ����) �迭 ������
@param pbszCounter : ī���� �ʱ� ��
@param pbszNonce : IV �� Counter�� type�� ���� ��Ʈ ����� ��� ��
*/
void InitNonce_HIGHT( IN NONCE_TYPE type, IN BYTE *pbszIV, IN BYTE *pbszCounter, OUT BYTE *pbszNonce );

/**
@brief BYTE �迭�� int �迭�� ��ȯ�Ѵ�.
@param in :��ȯ�� BYTE ������
@param inLen : ��ȯ�� BYTE �迭 ����
@return ���ڷ� ���� BYTE �迭�� int�� ��ȯ�� �����͸� ��ȯ�Ѵ�. (���������� malloc������ free�� �� ����� �Ѵ�)
@remarks ���������� ������ ����� �Լ��� SEED CTR, CBC, HIGHT CTR, CBC�� ������ include �� 
���� �Լ��� ��� �浹 ������ �ڿ� ������ �� �ֵ��� ���带 ���δ�.
*/
DWORD* chartoint32_for_HIGHT_CTR( IN BYTE *in, IN int inLen );

/**
@brief int �迭�� BYTE �迭�� ��ȯ�Ѵ�.
@param in :��ȯ�� int ������
@param inLen : ��ȯ�� int �迭 ����
@return ���ڷ� ���� int �迭�� char�� ��ȯ�� �����͸� ��ȯ�Ѵ�. (���������� malloc������ free�� �� ����� �Ѵ�)
@remarks ���������� ������ ����� �Լ��� SEED CTR, CBC, HIGHT CTR, CBC�� ������ include �� 
���� �Լ��� ��� �浹 ������ �ڿ� ������ �� �ֵ��� ���带 ���δ�.
*/
BYTE* int32tochar_for_HIGHT_CTR( IN DWORD *in, IN int inLen );

/**
@brief HIGHT CTR �˰��� �ʱ�ȭ �Լ�
@param pInfo : CTR ���ο��� ���Ǵ� ����ü�ν� ������ �����ϸ� �ȵȴ�.(�޸� �Ҵ�Ǿ� �־�� �Ѵ�.)
@param enc : ��ȣȭ �� ��ȣȭ ��� ����
@param pUserKey : ����ڰ� �����ϴ� �Է� Ű(16 BYTE)
@param pszbIV : ����ڰ� �����ϴ� �ʱ�ȭ ����(16 BYTE)
*/
void HIGHT_CTR_init( OUT KISA_HIGHT_INFO *pInfo, IN KISA_ENC_DEC enc, IN BYTE *pUserKey, IN BYTE *pszbCTR );

/**
@brief HIGHT CTR ���� �� ��ȣȭ/��ȣȭ �Լ�
@param pInfo : HIGHT_CTR_init ���� ������ KISA_HIGHT_INFO ����ü
@param in : ��/��ȣ�� ( ���� chartoint32_for_HIGHT_CBC�� ����Ͽ� int�� ��ȯ�� ������)
@param inLen : ��/��ȣ�� ����(BYTE ����)
@param out : ��/��ȣ�� ����
@param outLen : ����� ��/��ȣ���� ����(BYTE ������ �Ѱ��ش�)
@return 0: inLen�� ���� 0���� ���� ���, KISA_HIGHT_INFO ����ü�� in, out�� �� �����Ͱ� �Ҵ�Ǿ��� ���
        1: ����
*/
int HIGHT_CTR_Process( OUT KISA_HIGHT_INFO *pInfo, IN DWORD *in, IN int inLen, IN DWORD *out, IN int *outLen );

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
int HIGHT_CTR_Encrypt( IN BYTE *pbszUserKey, IN BYTE *pszbCounter, IN BYTE *pbInputText, IN int in_offset, IN int nInputTextLen, OUT BYTE *pbszOutputText );

/**
@brief ó���ϰ��� �ϴ� �����Ͱ� ���� ��쿡 ���
@param pbszUserKey : ����ڰ� �����ϴ� �Է� Ű(16 BYTE)
@param pszbIV : ����ڰ� �����ϴ� �ʱ�ȭ ����(16 BYTE)
@param pbszCipherText : ��ȣ��
@param nCipherTextLen : ��ȣ�� ����(BYTE ������ �򹮱���)
@param pbszPlainText : �� ��� ����
@return ��ȣȭ�� ����� ����(char ����)
*/
int HIGHT_CTR_Decrypt( IN BYTE *pbszUserKey, IN BYTE *pszbCounter, IN BYTE *pbInputText, IN int in_offset, IN int nInputTextLen, OUT BYTE *pbszOutputText );

#ifdef  __cplusplus
}
#endif

#endif