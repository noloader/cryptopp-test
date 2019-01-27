/**
@file KISA_HIGHT_ECB.java
@brief HIGHT ECB ��ȣ �˰���
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/


public class KISA_HIGHT_ECB {

	// DEFAULT : JAVA = BIG_ENDIAN
	private static int ENDIAN = Common.BIG_ENDIAN;

	private static final byte[] Delta = new byte[] 
	{
		(byte)0x5A,(byte)0x6D,(byte)0x36,(byte)0x1B,(byte)0x0D,(byte)0x06,(byte)0x03,(byte)0x41,
		(byte)0x60,(byte)0x30,(byte)0x18,(byte)0x4C,(byte)0x66,(byte)0x33,(byte)0x59,(byte)0x2C,
		(byte)0x56,(byte)0x2B,(byte)0x15,(byte)0x4A,(byte)0x65,(byte)0x72,(byte)0x39,(byte)0x1C,
		(byte)0x4E,(byte)0x67,(byte)0x73,(byte)0x79,(byte)0x3C,(byte)0x5E,(byte)0x6F,(byte)0x37,
		(byte)0x5B,(byte)0x2D,(byte)0x16,(byte)0x0B,(byte)0x05,(byte)0x42,(byte)0x21,(byte)0x50,
		(byte)0x28,(byte)0x54,(byte)0x2A,(byte)0x55,(byte)0x6A,(byte)0x75,(byte)0x7A,(byte)0x7D,
		(byte)0x3E,(byte)0x5F,(byte)0x2F,(byte)0x17,(byte)0x4B,(byte)0x25,(byte)0x52,(byte)0x29,
		(byte)0x14,(byte)0x0A,(byte)0x45,(byte)0x62,(byte)0x31,(byte)0x58,(byte)0x6C,(byte)0x76,
		(byte)0x3B,(byte)0x1D,(byte)0x0E,(byte)0x47,(byte)0x63,(byte)0x71,(byte)0x78,(byte)0x7C,
		(byte)0x7E,(byte)0x7F,(byte)0x3F,(byte)0x1F,(byte)0x0F,(byte)0x07,(byte)0x43,(byte)0x61,
		(byte)0x70,(byte)0x38,(byte)0x5C,(byte)0x6E,(byte)0x77,(byte)0x7B,(byte)0x3D,(byte)0x1E,
		(byte)0x4F,(byte)0x27,(byte)0x53,(byte)0x69,(byte)0x34,(byte)0x1A,(byte)0x4D,(byte)0x26,
		(byte)0x13,(byte)0x49,(byte)0x24,(byte)0x12,(byte)0x09,(byte)0x04,(byte)0x02,(byte)0x01,
		(byte)0x40,(byte)0x20,(byte)0x10,(byte)0x08,(byte)0x44,(byte)0x22,(byte)0x11,(byte)0x48,
		(byte)0x64,(byte)0x32,(byte)0x19,(byte)0x0C,(byte)0x46,(byte)0x23,(byte)0x51,(byte)0x68,
		(byte)0x74,(byte)0x3A,(byte)0x5D,(byte)0x2E,(byte)0x57,(byte)0x6B,(byte)0x35,(byte)0x5A
	};

	private static final byte F0[] = new byte[] 
	{
		(byte)0x00,(byte)0x86,(byte)0x0D,(byte)0x8B,(byte)0x1A,(byte)0x9C,(byte)0x17,(byte)0x91,
		(byte)0x34,(byte)0xB2,(byte)0x39,(byte)0xBF,(byte)0x2E,(byte)0xA8,(byte)0x23,(byte)0xA5,
		(byte)0x68,(byte)0xEE,(byte)0x65,(byte)0xE3,(byte)0x72,(byte)0xF4,(byte)0x7F,(byte)0xF9,
		(byte)0x5C,(byte)0xDA,(byte)0x51,(byte)0xD7,(byte)0x46,(byte)0xC0,(byte)0x4B,(byte)0xCD,
		(byte)0xD0,(byte)0x56,(byte)0xDD,(byte)0x5B,(byte)0xCA,(byte)0x4C,(byte)0xC7,(byte)0x41,
		(byte)0xE4,(byte)0x62,(byte)0xE9,(byte)0x6F,(byte)0xFE,(byte)0x78,(byte)0xF3,(byte)0x75,
		(byte)0xB8,(byte)0x3E,(byte)0xB5,(byte)0x33,(byte)0xA2,(byte)0x24,(byte)0xAF,(byte)0x29,
		(byte)0x8C,(byte)0x0A,(byte)0x81,(byte)0x07,(byte)0x96,(byte)0x10,(byte)0x9B,(byte)0x1D,
		(byte)0xA1,(byte)0x27,(byte)0xAC,(byte)0x2A,(byte)0xBB,(byte)0x3D,(byte)0xB6,(byte)0x30,
		(byte)0x95,(byte)0x13,(byte)0x98,(byte)0x1E,(byte)0x8F,(byte)0x09,(byte)0x82,(byte)0x04,
		(byte)0xC9,(byte)0x4F,(byte)0xC4,(byte)0x42,(byte)0xD3,(byte)0x55,(byte)0xDE,(byte)0x58,
		(byte)0xFD,(byte)0x7B,(byte)0xF0,(byte)0x76,(byte)0xE7,(byte)0x61,(byte)0xEA,(byte)0x6C,
		(byte)0x71,(byte)0xF7,(byte)0x7C,(byte)0xFA,(byte)0x6B,(byte)0xED,(byte)0x66,(byte)0xE0,
		(byte)0x45,(byte)0xC3,(byte)0x48,(byte)0xCE,(byte)0x5F,(byte)0xD9,(byte)0x52,(byte)0xD4,
		(byte)0x19,(byte)0x9F,(byte)0x14,(byte)0x92,(byte)0x03,(byte)0x85,(byte)0x0E,(byte)0x88,
		(byte)0x2D,(byte)0xAB,(byte)0x20,(byte)0xA6,(byte)0x37,(byte)0xB1,(byte)0x3A,(byte)0xBC,
		(byte)0x43,(byte)0xC5,(byte)0x4E,(byte)0xC8,(byte)0x59,(byte)0xDF,(byte)0x54,(byte)0xD2,
		(byte)0x77,(byte)0xF1,(byte)0x7A,(byte)0xFC,(byte)0x6D,(byte)0xEB,(byte)0x60,(byte)0xE6,
		(byte)0x2B,(byte)0xAD,(byte)0x26,(byte)0xA0,(byte)0x31,(byte)0xB7,(byte)0x3C,(byte)0xBA,
		(byte)0x1F,(byte)0x99,(byte)0x12,(byte)0x94,(byte)0x05,(byte)0x83,(byte)0x08,(byte)0x8E,
		(byte)0x93,(byte)0x15,(byte)0x9E,(byte)0x18,(byte)0x89,(byte)0x0F,(byte)0x84,(byte)0x02,
		(byte)0xA7,(byte)0x21,(byte)0xAA,(byte)0x2C,(byte)0xBD,(byte)0x3B,(byte)0xB0,(byte)0x36,
		(byte)0xFB,(byte)0x7D,(byte)0xF6,(byte)0x70,(byte)0xE1,(byte)0x67,(byte)0xEC,(byte)0x6A,
		(byte)0xCF,(byte)0x49,(byte)0xC2,(byte)0x44,(byte)0xD5,(byte)0x53,(byte)0xD8,(byte)0x5E,
		(byte)0xE2,(byte)0x64,(byte)0xEF,(byte)0x69,(byte)0xF8,(byte)0x7E,(byte)0xF5,(byte)0x73,
		(byte)0xD6,(byte)0x50,(byte)0xDB,(byte)0x5D,(byte)0xCC,(byte)0x4A,(byte)0xC1,(byte)0x47,
		(byte)0x8A,(byte)0x0C,(byte)0x87,(byte)0x01,(byte)0x90,(byte)0x16,(byte)0x9D,(byte)0x1B,
		(byte)0xBE,(byte)0x38,(byte)0xB3,(byte)0x35,(byte)0xA4,(byte)0x22,(byte)0xA9,(byte)0x2F,
		(byte)0x32,(byte)0xB4,(byte)0x3F,(byte)0xB9,(byte)0x28,(byte)0xAE,(byte)0x25,(byte)0xA3,
		(byte)0x06,(byte)0x80,(byte)0x0B,(byte)0x8D,(byte)0x1C,(byte)0x9A,(byte)0x11,(byte)0x97,
		(byte)0x5A,(byte)0xDC,(byte)0x57,(byte)0xD1,(byte)0x40,(byte)0xC6,(byte)0x4D,(byte)0xCB,
		(byte)0x6E,(byte)0xE8,(byte)0x63,(byte)0xE5,(byte)0x74,(byte)0xF2,(byte)0x79,(byte)0xFF
	};

	private static final byte F1[] = new byte[] 
	{
		(byte)0x00,(byte)0x58,(byte)0xB0,(byte)0xE8,(byte)0x61,(byte)0x39,(byte)0xD1,(byte)0x89,
		(byte)0xC2,(byte)0x9A,(byte)0x72,(byte)0x2A,(byte)0xA3,(byte)0xFB,(byte)0x13,(byte)0x4B,
		(byte)0x85,(byte)0xDD,(byte)0x35,(byte)0x6D,(byte)0xE4,(byte)0xBC,(byte)0x54,(byte)0x0C,
		(byte)0x47,(byte)0x1F,(byte)0xF7,(byte)0xAF,(byte)0x26,(byte)0x7E,(byte)0x96,(byte)0xCE,
		(byte)0x0B,(byte)0x53,(byte)0xBB,(byte)0xE3,(byte)0x6A,(byte)0x32,(byte)0xDA,(byte)0x82,
		(byte)0xC9,(byte)0x91,(byte)0x79,(byte)0x21,(byte)0xA8,(byte)0xF0,(byte)0x18,(byte)0x40,
		(byte)0x8E,(byte)0xD6,(byte)0x3E,(byte)0x66,(byte)0xEF,(byte)0xB7,(byte)0x5F,(byte)0x07,
		(byte)0x4C,(byte)0x14,(byte)0xFC,(byte)0xA4,(byte)0x2D,(byte)0x75,(byte)0x9D,(byte)0xC5,
		(byte)0x16,(byte)0x4E,(byte)0xA6,(byte)0xFE,(byte)0x77,(byte)0x2F,(byte)0xC7,(byte)0x9F,
		(byte)0xD4,(byte)0x8C,(byte)0x64,(byte)0x3C,(byte)0xB5,(byte)0xED,(byte)0x05,(byte)0x5D,
		(byte)0x93,(byte)0xCB,(byte)0x23,(byte)0x7B,(byte)0xF2,(byte)0xAA,(byte)0x42,(byte)0x1A,
		(byte)0x51,(byte)0x09,(byte)0xE1,(byte)0xB9,(byte)0x30,(byte)0x68,(byte)0x80,(byte)0xD8,
		(byte)0x1D,(byte)0x45,(byte)0xAD,(byte)0xF5,(byte)0x7C,(byte)0x24,(byte)0xCC,(byte)0x94,
		(byte)0xDF,(byte)0x87,(byte)0x6F,(byte)0x37,(byte)0xBE,(byte)0xE6,(byte)0x0E,(byte)0x56,
		(byte)0x98,(byte)0xC0,(byte)0x28,(byte)0x70,(byte)0xF9,(byte)0xA1,(byte)0x49,(byte)0x11,
		(byte)0x5A,(byte)0x02,(byte)0xEA,(byte)0xB2,(byte)0x3B,(byte)0x63,(byte)0x8B,(byte)0xD3,
		(byte)0x2C,(byte)0x74,(byte)0x9C,(byte)0xC4,(byte)0x4D,(byte)0x15,(byte)0xFD,(byte)0xA5,
		(byte)0xEE,(byte)0xB6,(byte)0x5E,(byte)0x06,(byte)0x8F,(byte)0xD7,(byte)0x3F,(byte)0x67,
		(byte)0xA9,(byte)0xF1,(byte)0x19,(byte)0x41,(byte)0xC8,(byte)0x90,(byte)0x78,(byte)0x20,
		(byte)0x6B,(byte)0x33,(byte)0xDB,(byte)0x83,(byte)0x0A,(byte)0x52,(byte)0xBA,(byte)0xE2,
		(byte)0x27,(byte)0x7F,(byte)0x97,(byte)0xCF,(byte)0x46,(byte)0x1E,(byte)0xF6,(byte)0xAE,
		(byte)0xE5,(byte)0xBD,(byte)0x55,(byte)0x0D,(byte)0x84,(byte)0xDC,(byte)0x34,(byte)0x6C,
		(byte)0xA2,(byte)0xFA,(byte)0x12,(byte)0x4A,(byte)0xC3,(byte)0x9B,(byte)0x73,(byte)0x2B,
		(byte)0x60,(byte)0x38,(byte)0xD0,(byte)0x88,(byte)0x01,(byte)0x59,(byte)0xB1,(byte)0xE9,
		(byte)0x3A,(byte)0x62,(byte)0x8A,(byte)0xD2,(byte)0x5B,(byte)0x03,(byte)0xEB,(byte)0xB3,
		(byte)0xF8,(byte)0xA0,(byte)0x48,(byte)0x10,(byte)0x99,(byte)0xC1,(byte)0x29,(byte)0x71,
		(byte)0xBF,(byte)0xE7,(byte)0x0F,(byte)0x57,(byte)0xDE,(byte)0x86,(byte)0x6E,(byte)0x36,
		(byte)0x7D,(byte)0x25,(byte)0xCD,(byte)0x95,(byte)0x1C,(byte)0x44,(byte)0xAC,(byte)0xF4,
		(byte)0x31,(byte)0x69,(byte)0x81,(byte)0xD9,(byte)0x50,(byte)0x08,(byte)0xE0,(byte)0xB8,
		(byte)0xF3,(byte)0xAB,(byte)0x43,(byte)0x1B,(byte)0x92,(byte)0xCA,(byte)0x22,(byte)0x7A,
		(byte)0xB4,(byte)0xEC,(byte)0x04,(byte)0x5C,(byte)0xD5,(byte)0x8D,(byte)0x65,(byte)0x3D,
		(byte)0x76,(byte)0x2E,(byte)0xC6,(byte)0x9E,(byte)0x17,(byte)0x4F,(byte)0xA7,(byte)0xFF
	};
	
	private static final int BLOCK_SIZE_HIGHT = 8;
	private static final int BLOCK_SIZE_HIGHT_INT = 2;
	
	private static void BLOCK_XOR_HIGHT(int[] OUT_VALUE, int out_value_offset, int[] IN_VALUE1, int in_value1_offset, int[] IN_VALUE2, int in_value2_offset) {
		OUT_VALUE[out_value_offset+0] = (in_value1_offset<IN_VALUE1.length?IN_VALUE1[in_value1_offset+0]:0) ^ (in_value2_offset<IN_VALUE2.length?IN_VALUE2[in_value2_offset+0]:0);
		OUT_VALUE[out_value_offset+1] = (in_value1_offset+1<IN_VALUE1.length?IN_VALUE1[in_value1_offset+1]:0) ^ (in_value2_offset+1<IN_VALUE2.length?IN_VALUE2[in_value2_offset+1]:0);
	}
	
	private static void EncIni_Transformation(int[] t, byte x0, byte x2, byte x4, byte x6, byte mk0, byte mk1, byte mk2, byte mk3) {
		t[0] = ((0x0ff&(int)x0) + (0x0ff&(int)mk0)) & 0x0ff;
		t[2] = ((0x0ff&(int)x2) ^ (0x0ff&(int)mk1)) & 0x0ff;
		t[4] = ((0x0ff&(int)x4) + (0x0ff&(int)mk2)) & 0x0ff;
		t[6] = ((0x0ff&(int)x6) ^ (0x0ff&(int)mk3)) & 0x0ff;
	}
	
	private static void EncFin_Transformation(byte[] out, int x0, int x2, int x4, int x6, int mk0, int mk1, int mk2, int mk3) {
		out[0] = (byte)(x0 + mk0);
		out[2] = (byte)(x2 ^ mk1);
		out[4] = (byte)(x4 + mk2);
		out[6] = (byte)(x6 ^ mk3);
	}
	
	private static void Round(int[] x, int i7, int i6, int i5, int i4, int i3, int i2, int i1, int i0, byte[] key, int key_offset) {
		x[i1] = (x[i1] + ((F1[x[i0]] ^ key[key_offset+0])&0x0ff)) & 0x0ff;
		x[i3] = (x[i3] ^ ((F0[x[i2]] + key[key_offset+1])&0x0ff)) & 0x0ff;
		x[i5] = (x[i5] + ((F1[x[i4]] ^ key[key_offset+2])&0x0ff)) & 0x0ff;
		x[i7] = (x[i7] ^ ((F0[x[i6]] + key[key_offset+3])&0x0ff)) & 0x0ff;
	}

	private static void KISA_HIGHT_ECB_encrypt_forECB(byte[] pbszIN_Key128, byte[] pbszUserKey, final int[] in, int in_offset, int[] out, int out_offset) {
		int in_length = in.length - in_offset;
		int out_length = out.length - out_offset;
		byte[] b_in = new byte[in_length * 4];
		byte[] b_out = new byte[out_length * 4];
		
		for(int i=0; i<in_length; i++) {
			Common.int_to_byte(b_in, i*4, in, in_offset+i, ENDIAN);
		}
		
		for(int i=0; i<out_length; i++) {
			Common.int_to_byte(b_out, i*4, out, out_offset+i, ENDIAN);
		}
		
		KISA_HIGHT_ECB_encrypt_forECB(pbszIN_Key128, pbszUserKey, b_in, b_out);
		
		for(int i=0; i<in_length; i++) {
			Common.byte_to_int(in, in_offset+i, b_in, i*4, ENDIAN);
		}
		
		for(int i=0; i<out_length; i++) {
			Common.byte_to_int(out, out_offset+i, b_out, i*4, ENDIAN);
		}
		
	}
	
	private static void KISA_HIGHT_ECB_encrypt_forECB(byte[] pbszIN_Key128, byte[] pbszUserKey, final byte[] in, byte[] out) {
		int[] t = new int[] { 0, 0, 0, 0, 0, 0, 0, 0 };
		byte[] key, key2;
		int key_offset = 0;
		
		key = pbszIN_Key128;
		key2 = pbszUserKey;
		
		t[1] = in[1]; t[3] = in[3]; t[5] = in[5]; t[7] = in[7];
		EncIni_Transformation(t, in[0], in[2], in[4], in[6], key2[12], key2[13], key2[14], key2[15] );
		
		Round(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset += 4;		// 1
		Round(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset += 4;		// 2
		Round(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset += 4;		// 3
		Round(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset += 4;		// 4
		Round(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset += 4;		// 5
		Round(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset += 4;		// 6
		Round(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset += 4;		// 7
		Round(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset += 4;		// 8
		Round(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset += 4;		// 9
		Round(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset += 4;		// 10
		Round(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset += 4;		// 11
		Round(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset += 4;		// 12
		Round(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset += 4;		// 13
		Round(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset += 4;		// 14
		Round(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset += 4;		// 15
		Round(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset += 4;		// 16
		Round(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset += 4;		// 17
		Round(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset += 4;		// 18
		Round(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset += 4;		// 19
		Round(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset += 4;		// 20
		Round(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset += 4;		// 21
		Round(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset += 4;		// 22
		Round(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset += 4;		// 23
		Round(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset += 4;		// 24
		Round(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset += 4;		// 25
		Round(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset += 4;		// 26
		Round(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset += 4;		// 27
		Round(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset += 4;		// 28
		Round(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset += 4;		// 29
		Round(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset += 4;		// 30
		Round(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset += 4;		// 31
		Round(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset);						// 32
		
		EncFin_Transformation(out, t[1], t[3], t[5], t[7], key2[0], key2[1], key2[2], key2[3] );
		
		out[1] = (byte)t[2]; out[3] = (byte)t[4]; out[5] = (byte)t[6]; out[7] = (byte)t[0];
	}

	private static void DecIni_Transformation(int[] t, byte x0, byte x2, byte x4, byte x6, byte mk0, byte mk1, byte mk2, byte mk3) {
		t[0] = (((0x0ff&(int)x0) - (0x0ff&(int)mk0))) & 0x0ff;
		t[2] = (((0x0ff&(int)x2) ^ (0x0ff&(int)mk1))) & 0x0ff;
		t[4] = (((0x0ff&(int)x4) - (0x0ff&(int)mk2))) & 0x0ff;
		t[6] = (((0x0ff&(int)x6) ^ (0x0ff&(int)mk3))) & 0x0ff;
	}
	
	private static void DecFin_Transformation(byte[] out, int x0, int x2, int x4, int x6, int mk0, int mk1, int mk2, int mk3) {
		out[0] = (byte)(x0 - mk0);
		out[2] = (byte)(x2 ^ mk1);
		out[4] = (byte)(x4 - mk2);
		out[6] = (byte)(x6 ^ mk3);
	}

	private static void DRound(int[] x, int i7, int i6, int i5, int i4, int i3, int i2, int i1, int i0, byte[] key, int key_offset) {
		x[i1] = (x[i1] - ((F1[x[i0]] ^ key[key_offset+0])&0x0ff)) & 0x0ff;
		x[i3] = (x[i3] ^ ((F0[x[i2]] + key[key_offset+1])&0x0ff)) & 0x0ff;
		x[i5] = (x[i5] - ((F1[x[i4]] ^ key[key_offset+2])&0x0ff)) & 0x0ff;
		x[i7] = (x[i7] ^ ((F0[x[i6]] + key[key_offset+3])&0x0ff)) & 0x0ff;
	}

	private static void KISA_HIGHT_ECB_decrypt_forECB(byte[] pbszIN_Key128, byte[] pbszUserKey, final int[] in, int in_offset, int[] out, int out_offset) {
		int in_length = in.length - in_offset;
		int out_length = out.length - out_offset;
		byte[] b_in = new byte[in_length * 4];
		byte[] b_out = new byte[out_length * 4];
		
		for(int i=0; i<in_length; i++) {
			Common.int_to_byte(b_in, i*4, in, in_offset+i, ENDIAN);
		}
		
		for(int i=0; i<out_length; i++) {
			Common.int_to_byte(b_out, i*4, out, out_offset+i, ENDIAN);
		}
		
		KISA_HIGHT_ECB_decrypt_forECB(pbszIN_Key128, pbszUserKey, b_in, b_out);
		
		for(int i=0; i<in_length; i++) {
			Common.byte_to_int(in, in_offset+i, b_in, i*4, ENDIAN);
		}
		
		for(int i=0; i<out_length; i++) {
			Common.byte_to_int(out, out_offset+i, b_out, i*4, ENDIAN);
		}
		
	}

	private static void KISA_HIGHT_ECB_decrypt_forECB(byte[] pbszIN_Key128, byte[] pbszUserKey, final byte[] in, byte[] out) {
		int[] t = new int[8];
		byte[] key, key2;
		int key_offset;
		
		key = pbszIN_Key128;
		key2 = pbszUserKey;
		key_offset = 124;
		
		t[1] = in[1]; t[3] = in[3]; t[5] = in[5]; t[7] = in[7];
		DecIni_Transformation(t, in[0], in[2], in[4], in[6], key2[0], key2[1], key2[2], key2[3] );
		
		DRound(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset -= 4;
		DRound(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset -= 4;
		DRound(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset -= 4;
		DRound(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset -= 4;
		DRound(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset -= 4;
		DRound(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset -= 4;
		DRound(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset -= 4;
		DRound(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset -= 4;
		DRound(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset -= 4;
		DRound(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset -= 4;
		DRound(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset -= 4;
		DRound(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset -= 4;
		DRound(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset -= 4;
		DRound(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset -= 4;
		DRound(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset -= 4;
		DRound(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset -= 4;
		DRound(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset -= 4;
		DRound(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset -= 4;
		DRound(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset -= 4;
		DRound(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset -= 4;
		DRound(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset -= 4;
		DRound(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset -= 4;
		DRound(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset -= 4;
		DRound(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset); key_offset -= 4;
		DRound(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset); key_offset -= 4;
		DRound(t, 0, 7, 6, 5, 4, 3, 2, 1, key, key_offset); key_offset -= 4;
		DRound(t, 1, 0, 7, 6, 5, 4, 3, 2, key, key_offset); key_offset -= 4;
		DRound(t, 2, 1, 0, 7, 6, 5, 4, 3, key, key_offset); key_offset -= 4;
		DRound(t, 3, 2, 1, 0, 7, 6, 5, 4, key, key_offset); key_offset -= 4;
		DRound(t, 4, 3, 2, 1, 0, 7, 6, 5, key, key_offset); key_offset -= 4;
		DRound(t, 5, 4, 3, 2, 1, 0, 7, 6, key, key_offset); key_offset -= 4;
		DRound(t, 6, 5, 4, 3, 2, 1, 0, 7, key, key_offset);
		
		DecFin_Transformation(out, t[7], t[1], t[3], t[5], key2[12], key2[13], key2[14], key2[15]);
		
		out[1] = (byte)t[0]; out[3] = (byte)t[2]; out[5] = (byte)t[4]; out[7] = (byte)t[6];
	}
	

	public static int[] chartoint32_for_HIGHT_ECB(byte[] in, int inLen) {
		int[] data;
		int len, i;
		
		if(inLen % 4 > 0)
			len = (inLen/4)+1;
		else
			len = (inLen/4);
		
		data = new int[len];
		
		for(i=0;i<len;i++)
		{
			Common.byte_to_int(data, i, in, i*4, ENDIAN);
		}
		
		return data;
	}
	

	public static byte[] int32tochar_for_HIGHT_ECB(int in[], int inLen) {
		byte[] data;
		int i;

		data = new byte[inLen];
		if(ENDIAN != Common.BIG_ENDIAN) {
			for(i=0;i<inLen;i++)
			{
				data[i] = (byte)(in[i/4] >> ((i%4)*8));
			}
		} else {
			for(i=0;i<inLen;i++)
			{
				data[i] = (byte)(in[i/4] >> ((3-(i%4))*8));
			}			
		}

		return data;
	}
	

	public static int HIGHT_ECB_init( KISA_HIGHT_INFO pInfo, KISA_ENC_DEC enc, byte[] pUserKey )
	{
		byte i, j;

		if( null == pInfo || 
			null == pUserKey )
			return 0;

		pInfo.encrypt = enc.value;
		Common.arraycopy(pInfo.userKey, pUserKey, 16);

		for(i=0 ; i < BLOCK_SIZE_HIGHT ; i++)
		{
			for(j=0 ; j < BLOCK_SIZE_HIGHT ; j++)
				pInfo.hight_key.key_data[ 16*i + j ] = (byte)(pUserKey[(j-i)&7    ] + Delta[ 16*i + j ]);

			for(j=0 ; j < BLOCK_SIZE_HIGHT ; j++)
				pInfo.hight_key.key_data[ 16*i + j + 8 ] = (byte)(pUserKey[((j-i)&7)+8] + Delta[ 16*i + j + 8 ]);
		}
		
		return 1;
	}
	

	public static int HIGHT_ECB_Process( KISA_HIGHT_INFO pInfo, int []in, int inLen, int []out, int []outLen )
	{
		int nCurrentCount = BLOCK_SIZE_HIGHT;
		int in_offset = 0;
		int out_offset = 0;



		if( null == pInfo ||
			null == in ||
			null == out ||
			0 > inLen )
			return 0;

		
		if( KISA_ENC_DEC._KISA_ENCRYPT == pInfo.encrypt )
		{
			in_offset = 0;
			out_offset = 0;
					
			while( nCurrentCount <= inLen )
			{
				KISA_HIGHT_ECB_encrypt_forECB( pInfo.hight_key.key_data, pInfo.userKey, in, in_offset, out, out_offset );
				nCurrentCount += BLOCK_SIZE_HIGHT;
				in_offset += BLOCK_SIZE_HIGHT_INT;
				out_offset += BLOCK_SIZE_HIGHT_INT;
			}
			
			outLen[0] = nCurrentCount - BLOCK_SIZE_HIGHT; 
			pInfo.buffer_length = inLen - outLen[0];

			Common.memcpy(pInfo.ecb_buffer, in, in_offset, pInfo.buffer_length);
		}
		else
		{
			in_offset = 0;
			out_offset = 0;

			while( nCurrentCount <= inLen )
			{
				KISA_HIGHT_ECB_decrypt_forECB( pInfo.hight_key.key_data, pInfo.userKey, in, in_offset, out, out_offset );
				nCurrentCount += BLOCK_SIZE_HIGHT;
				in_offset += BLOCK_SIZE_HIGHT_INT;
				out_offset += BLOCK_SIZE_HIGHT_INT;
			}
				
			outLen[0] = nCurrentCount - BLOCK_SIZE_HIGHT;
			Common.memcpy(pInfo.ecb_last_block, out, out_offset-BLOCK_SIZE_HIGHT_INT, BLOCK_SIZE_HIGHT);
		}

		return 1;
	}


	public static int HIGHT_ECB_Close( KISA_HIGHT_INFO pInfo, int[] out, int out_offset, int[] outLen )
	{
		int nPaddngLeng;
		int i;

		outLen[0] = 0;
		
		if( null == out )
			return 0;

		if( KISA_ENC_DEC._KISA_ENCRYPT == pInfo.encrypt )
		{
			nPaddngLeng = BLOCK_SIZE_HIGHT - pInfo.buffer_length;
			for( i = pInfo.buffer_length; i<BLOCK_SIZE_HIGHT; i++ ) {
				Common.set_byte_for_int(pInfo.ecb_buffer, i, (byte)nPaddngLeng, ENDIAN);
			}
			KISA_HIGHT_ECB_encrypt_forECB( pInfo.hight_key.key_data, pInfo.userKey, pInfo.ecb_buffer, 0, out, out_offset );

			outLen[0] = BLOCK_SIZE_HIGHT;

		}
		else
		{
			nPaddngLeng = (Common.get_byte_for_int(pInfo.ecb_last_block, BLOCK_SIZE_HIGHT-1, ENDIAN));


			if( nPaddngLeng > 0 && nPaddngLeng <= BLOCK_SIZE_HIGHT )
			{
				for(i=nPaddngLeng; i>0; i-- )
				{
					Common.set_byte_for_int(out, out_offset-i, (byte)0x00, ENDIAN);
				}

				outLen[0] = nPaddngLeng;
			}
			else
				return 0;

			
		}
		return 1;
	}
	

	public static byte[] HIGHT_ECB_Encrypt( byte[] pbszUserKey, byte[] message, int message_offset, int message_length )
	{
		KISA_HIGHT_INFO info = new KISA_HIGHT_INFO();
		int[] outbuf;
		int[] data;
		byte[] cdata;
		int outlen = 0;
		int nRetOutLeng[] = { 0 };
		int nPaddingLeng[] = { 0 };
		
		byte[] pbszPlainText = new byte[message_length];
		System.arraycopy(message, message_offset, pbszPlainText, 0, message_length);
		int nPlainTextLen = pbszPlainText.length;
		
		
		int nPlainTextPadding = BLOCK_SIZE_HIGHT - (nPlainTextLen % BLOCK_SIZE_HIGHT);
		byte []newpbszPlainText = new byte[nPlainTextLen+nPlainTextPadding];
		Common.arraycopy(newpbszPlainText, pbszPlainText, nPlainTextLen);
		
		byte[] pbszCipherText = new byte[newpbszPlainText.length];
		
		HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_ENCRYPT, pbszUserKey );

		outlen = ( (newpbszPlainText.length/BLOCK_SIZE_HIGHT) ) * BLOCK_SIZE_HIGHT_INT;
		outbuf = new int[outlen];
		data = chartoint32_for_HIGHT_ECB(newpbszPlainText, nPlainTextLen);

		HIGHT_ECB_Process( info, data, nPlainTextLen, outbuf, nRetOutLeng );
		HIGHT_ECB_Close( info, outbuf, (nRetOutLeng[0]/4), nPaddingLeng );

		cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]+nPaddingLeng[0]);
		Common.arraycopy(pbszCipherText, cdata, nRetOutLeng[0]+nPaddingLeng[0]);

		data = null;
		cdata = null;
		outbuf = null;

		return pbszCipherText;
	}


	public static byte[] HIGHT_ECB_Decrypt( byte[] pbszUserKey, byte[] message, int message_offset, int message_length )
	{
		KISA_HIGHT_INFO info = new KISA_HIGHT_INFO();
		int[] outbuf;
		int[] data;
		byte[] cdata;
		int outlen;
		int nRetOutLeng[] = {0};
		int nPaddingLeng[] = {0};

		byte[] pbszCipherText = new byte[message_length];
		System.arraycopy(message, message_offset, pbszCipherText, 0, message_length);
		int nCipherTextLen = pbszCipherText.length;
		
		if( (nCipherTextLen%BLOCK_SIZE_HIGHT) != 0 )
		{
			byte result[] = null;
			return result;
		}

		byte []newpbszCipherText = new byte[nCipherTextLen];
		Common.arraycopy(newpbszCipherText, pbszCipherText, nCipherTextLen);
			
		nCipherTextLen = newpbszCipherText.length;

		HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_DECRYPT, pbszUserKey );

		outlen = ( (nCipherTextLen/BLOCK_SIZE_HIGHT) ) *4 ;
		outbuf = new int[outlen];
		data = chartoint32_for_HIGHT_ECB(pbszCipherText, nCipherTextLen);

		HIGHT_ECB_Process( info, data, nCipherTextLen, outbuf, nRetOutLeng );
		
		if(HIGHT_ECB_Close( info, outbuf, (nRetOutLeng[0]), nPaddingLeng )==1)
		{
			cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]-nPaddingLeng[0]);
			byte[] pbszPlainText = new byte[nRetOutLeng[0]-nPaddingLeng[0]];
			Common.arraycopy(pbszPlainText, cdata, nRetOutLeng[0]-nPaddingLeng[0]);
			int pdmessage_length = nRetOutLeng[0] - nPaddingLeng[0];
			
			if(pdmessage_length < 0)
			{
				pdmessage_length = 0;
			}
			byte[] result = new byte[pdmessage_length];
			System.arraycopy(pbszPlainText, 0, result, 0, pdmessage_length);

			data = null;
			cdata = null;
			outbuf = null;

			return result;
		}
		else
		{
			byte result[] = null;		//FAIL
			return result;
		}
	}
	
	


	

	public static final class KISA_ENC_DEC {
		public static final int _KISA_DECRYPT = 0;
		public static final int _KISA_ENCRYPT = 1;
		
		public int value;
		
		public KISA_ENC_DEC(int value ) {
			this.value = value;
		}
		
		public static final KISA_ENC_DEC KISA_ENCRYPT = new KISA_ENC_DEC(_KISA_ENCRYPT);
		public static final KISA_ENC_DEC KISA_DECRYPT = new KISA_ENC_DEC(_KISA_DECRYPT);
		
	}

	public static final class KISA_HIGHT_KEY {
		public byte[] key_data = new byte[128];
		
		public void init() {
			for(int i=0; i<key_data.length; i++) {
				key_data[i] = 0;
			}
		}
	}

	public static final class KISA_HIGHT_INFO {
		public int encrypt;
		public KISA_HIGHT_KEY hight_key = new KISA_HIGHT_KEY();
		public byte[] userKey = new byte[16];
		public int ecb_buffer[] = new int[2];
		public int buffer_length;
		public int[] ecb_last_block = new int[2];
		
		public KISA_HIGHT_INFO() {
			encrypt = 0;
			hight_key.init();
			userKey[0] = 0;
			userKey[1] = 0;
			userKey[2] = 0;
			userKey[3] = 0;
			userKey[4] = 0;
			userKey[5] = 0;
			userKey[6] = 0;
			userKey[7] = 0;
			userKey[8] = 0;
			userKey[9] = 0;
			userKey[10] = 0;
			userKey[11] = 0;
			userKey[12] = 0;
			userKey[13] = 0;
			userKey[14] = 0;
			userKey[15] = 0;
			ecb_buffer[0] = ecb_buffer[1] = 0;
			buffer_length = 0;
			ecb_last_block[0] = ecb_last_block[1] = 0;
			
		}
			
		
	}


	public static class Common {
		
		public static final int BIG_ENDIAN = 0;
		public static final int LITTLE_ENDIAN = 1;

		public static void arraycopy(byte[] dst, byte[] src, int length) {
			for(int i=0; i<length; i++) {
				dst[i] = src[i];
			}
		}

		public static void arraycopy_offset(byte[] dst, int dst_offset, byte[] src, int src_offset, int length) {
			for(int i=0; i<length; i++) {
				dst[dst_offset+i] = src[src_offset+i];
			}
		}

		public static void arrayinit(byte[] dst, byte value, int length) {
			for(int i=0; i<length; i++) {
				dst[i] = value;
			}
		}
		
		public static void arrayinit_offset(byte[] dst, int dst_offset, byte value, int length) {
			for(int i=0; i<length; i++) {
				dst[dst_offset+i] = value;
			}
		}

		public static void memcpy(int[] dst, byte[] src, int length, int ENDIAN) {
			int iLen = length / 4;
			for(int i=0; i<iLen; i++) {
				byte_to_int(dst, i, src, i*4, ENDIAN);
			}
		}

		public static void memcpy(int[] dst, int[] src, int src_offset, int length) {
	    	int iLen = length / 4 + ((length % 4 != 0)?1:0);
			for(int i=0; i<iLen; i++) {
				dst[i] = src[src_offset+i];
			}
		}

		public static void set_byte_for_int(int[] dst, int b_offset, byte value, int ENDIAN) {
			if(ENDIAN == BIG_ENDIAN) {
				int shift_value = (3-b_offset%4)*8;
				int mask_value =  0x0ff << shift_value;
				int mask_value2 = ~mask_value;
				int value2 = (value&0x0ff) << shift_value;
				dst[b_offset/4] = (dst[b_offset/4] & mask_value2) | (value2 & mask_value);    
			} else {
				int shift_value = (b_offset%4)*8;
				int mask_value =  0x0ff << shift_value;
				int mask_value2 = ~mask_value;
				int value2 = (value&0x0ff) << shift_value;
				dst[b_offset/4] = (dst[b_offset/4] & mask_value2) | (value2 & mask_value);    
			}
		}
		
		public static byte get_byte_for_int(int[] src, int b_offset, int ENDIAN) {
			if(ENDIAN == BIG_ENDIAN) {
				int shift_value = (3-b_offset%4)*8;
				int mask_value =  0x0ff << shift_value;
				int value = (src[b_offset/4] & mask_value) >> shift_value;
				return (byte)value;
			} else {
				int shift_value = (b_offset%4)*8;
				int mask_value =  0x0ff << shift_value;
				int value = (src[b_offset/4] & mask_value) >> shift_value;
				return (byte)value;
			}
			
		}
		
		public static byte[] get_bytes_for_ints(int[] src, int offset, int ENDIAN) {
			int iLen = src.length-offset;
			byte[] result = new byte[(iLen)*4];
			for(int i=0; i<iLen; i++) {
				int_to_byte(result, i*4, src, offset+i, ENDIAN);
			}
			
			return result;
		}

		public static void byte_to_int(int[] dst, int dst_offset, byte[] src, int src_offset, int ENDIAN) {
			if(ENDIAN == BIG_ENDIAN) {
				dst[dst_offset] = ((0x0ff&src[src_offset]) << 24) | ((0x0ff&src[src_offset+1]) << 16) | ((0x0ff&src[src_offset+2]) << 8) | ((0x0ff&src[src_offset+3]));
			} else {
				dst[dst_offset] = ((0x0ff&src[src_offset])) | ((0x0ff&src[src_offset+1]) << 8) | ((0x0ff&src[src_offset+2]) << 16) | ((0x0ff&src[src_offset+3]) << 24);
			}
		}
		
		public static int byte_to_int(byte[] src, int src_offset, int ENDIAN) {
			if(ENDIAN == BIG_ENDIAN) {
				return ((0x0ff&src[src_offset]) << 24) | ((0x0ff&src[src_offset+1]) << 16) | ((0x0ff&src[src_offset+2]) << 8) | ((0x0ff&src[src_offset+3]));
			} else {
				return ((0x0ff&src[src_offset])) | ((0x0ff&src[src_offset+1]) << 8) | ((0x0ff&src[src_offset+2]) << 16) | ((0x0ff&src[src_offset+3]) << 24);
			}
		}

		public static int byte_to_int_big_endian(byte[] src, int src_offset) {
			return ((0x0ff&src[src_offset]) << 24) | ((0x0ff&src[src_offset+1]) << 16) | ((0x0ff&src[src_offset+2]) << 8) | ((0x0ff&src[src_offset+3]));
		}

		public static void int_to_byte(byte[] dst, int dst_offset, int[] src, int src_offset, int ENDIAN) {
			int_to_byte_unit(dst, dst_offset, src[src_offset], ENDIAN);
		}
		
		public static void int_to_byte_unit(byte[] dst, int dst_offset, int src, int ENDIAN) {
			if(ENDIAN == BIG_ENDIAN) {
				dst[dst_offset] = (byte)((src>> 24) & 0x0ff);
				dst[dst_offset+1] = (byte)((src >> 16) & 0x0ff);
				dst[dst_offset+2] = (byte)((src >> 8) & 0x0ff);
				dst[dst_offset+3] = (byte)((src) & 0x0ff);
			} else {
				dst[dst_offset] = (byte)((src) & 0x0ff);
				dst[dst_offset+1] = (byte)((src >> 8) & 0x0ff);
				dst[dst_offset+2] = (byte)((src >> 16) & 0x0ff);
				dst[dst_offset+3] = (byte)((src >> 24) & 0x0ff);
			}
			
		}

		public static void int_to_byte_unit_big_endian(byte[] dst, int dst_offset, int src) {
			dst[dst_offset] = (byte)((src>> 24) & 0x0ff);
			dst[dst_offset+1] = (byte)((src >> 16) & 0x0ff);
			dst[dst_offset+2] = (byte)((src >> 8) & 0x0ff);
			dst[dst_offset+3] = (byte)((src) & 0x0ff);
		}

		public static int URShift(int x, int n) {
			if(n == 0)
				return x;
			if(n >= 32)
				return 0;
			int v = x >> n;
			int v_mask = ~(0x80000000 >> (n-1));
			return v & v_mask;
		}
		
		public static final long INT_RANGE_MAX = (long)Math.pow(2, 32);

		public static long intToUnsigned(int x) {
			if(x >= 0)
				return x;
			return x + INT_RANGE_MAX;
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	public static void main(String[] args)
	{

// User secret key
		byte pbUserKey[]  = {(byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
		                     (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88, (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C};

		byte pbData[]     = {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F};
		  
	    
	    byte pbData1[]     = {(byte)0xAA, (byte)0xBB, (byte)0x00, (byte)0xCC
	    					, (byte)0xBB, (byte)0x00, (byte)0xFF, (byte)0xCC};		
	    
		
	    byte pbData2[]     = {(byte)0xD7, (byte)0x6D, (byte)0x0D, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E};		    
	    
	    byte pbData3[]     = {(byte)0xD7, (byte)0x6D, (byte)0x0D, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E
	    		, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E
	    		, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E
	    		, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E
	    		, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E
	    		, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E
	    		, (byte)0x18, (byte)0x32, (byte)0x7E, (byte)0xC5, (byte)0x62, (byte)0xB1, (byte)0x5E};		    
	    
	    
	    byte[] pbUserKey2 = {(byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
	    		(byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff};

    
	    
	    /*****************************************************************************************
	     * ��� 1
	     ******************************************************************************************/
	    
		System.out.print("[ Test HIGHT reference code ECB ]  ��� 1"+"\n");
		System.out.print("\n");
	    
		
		
		/*****************
		 * �׽�Ʈ ���� 1
		 *****************/	    
	    
		
		int PLAINTEXT_LENGTH = 8;
		int CIPHERTEXT_LENGTH = 16;
		
    	byte[] outary1 =  HIGHT_ECB_Encrypt(pbUserKey,   pbData1,  0, PLAINTEXT_LENGTH );
	    byte[] pbPlains1 = HIGHT_ECB_Decrypt(pbUserKey,   outary1,  0, CIPHERTEXT_LENGTH ) ;	   	    
	    
	    
	    
		System.out.print("Key\t\t: ");
	    for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
	    System.out.print("\n");
		System.out.print("Plaintext\t: ");
	    for (int i=0; i<8; i++)	System.out.print(Integer.toHexString(0xff&pbData1[i])+" ");
	    System.out.print("\n");
	    
	    
        System.out.print("Ciphertext(enc)\t: ");
	    for (int i=0; i<CIPHERTEXT_LENGTH; i++)
	    	System.out.print(Integer.toHexString(0xff&outary1[i])+" ");
	    System.out.print("\n");
	    
	    System.out.print("Plaintext(dec)\t: ");
	    for (int i=0; i<PLAINTEXT_LENGTH; i++)
	    	System.out.print(Integer.toHexString(0xff&pbPlains1[i])+" ");
	    System.out.print("\n");	
	    
	    
	    outary1 = null;
	    
	    


		
	    
	    /*****************************
	     * �׽�Ʈ ���� 2
	     ****************************/
	    
		System.out.print("\n\nKey\t\t: ");
		for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
		System.out.print("\n");
		System.out.print("Plaintext\t: ");
		for (int i=0; i<2; i++)	System.out.print(Integer.toHexString(0xff&pbData2[i])+" ");

		
		PLAINTEXT_LENGTH = 2;
		CIPHERTEXT_LENGTH = 8;
		
		byte[] outary2 =  HIGHT_ECB_Encrypt(pbUserKey,   pbData2,  0, PLAINTEXT_LENGTH );
		byte[] pbPlains2 = HIGHT_ECB_Decrypt(pbUserKey,   outary2,  0, CIPHERTEXT_LENGTH ) ;		
		
		
		System.out.print("\nCiphertext(enc)\t: ");
		for (int i=0; i<CIPHERTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&outary2[i])+" ");
		System.out.print("\n");
		
		System.out.print("Plaintext(dec)\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&pbPlains2[i])+" ");
		System.out.print("\n\n");
		
		
		outary2 = null;
		

		
		
	    /*****************************
	     * �׽�Ʈ ���� 3
	     ****************************/
		
		PLAINTEXT_LENGTH = 10;
		CIPHERTEXT_LENGTH = 16;
		
		System.out.print("\nKey\t\t: ");
		for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
		System.out.print("\n");
		System.out.print("Plaintext\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData[i])+" ");
	
		outary2 =  HIGHT_ECB_Encrypt(pbUserKey,   pbData,  0, PLAINTEXT_LENGTH );
		pbPlains2 = HIGHT_ECB_Decrypt(pbUserKey,   outary2,  0, CIPHERTEXT_LENGTH ) ;		
		
		
		System.out.print("\nCiphertext(enc)\t: ");
		for (int i=0; i<CIPHERTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&outary2[i])+" ");
		System.out.print("\n");
		
		System.out.print("Plaintext(dec)\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&pbPlains2[i])+" ");
		System.out.print("\n\n");
		
		outary2 = null;
		
		
	    /*****************************
	     * �׽�Ʈ ���� 4
	     ****************************/
		
		PLAINTEXT_LENGTH = 8;
		CIPHERTEXT_LENGTH = 16;
		
		System.out.print("\nKey\t\t: ");
		for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
		System.out.print("\n");
		System.out.print("Plaintext\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData[i])+" ");
	
		outary2 =  HIGHT_ECB_Encrypt(pbUserKey,   pbData,  0, PLAINTEXT_LENGTH );
		pbPlains2 = HIGHT_ECB_Decrypt(pbUserKey,   outary2,  0, CIPHERTEXT_LENGTH ) ;		
		
		
		System.out.print("\nCiphertext(enc)\t: ");
		for (int i=0; i<CIPHERTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&outary2[i])+" ");
		System.out.print("\n");
		
		System.out.print("Plaintext(dec)\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&pbPlains2[i])+" ");
		System.out.print("\n\n");	
		
		outary2 = null;
		

	    
	    /*****************************
	     * �׽�Ʈ ���� 5
	     ****************************/
		
	    byte[] pbUserKey3 = {(byte)0x88, (byte)0xe3, (byte)0x4f, (byte)0x8f, (byte)0x08, (byte)0x17, (byte)0x79, (byte)0xf1,
	    		(byte)0xe9, (byte)0xf3, (byte)0x94, (byte)0x37, (byte)0x0a, (byte)0xd4, (byte)0x05, (byte)0x89};
	    

		PLAINTEXT_LENGTH = 2;
		CIPHERTEXT_LENGTH = 8;
		
		System.out.print("\nKey\t\t: ");
		for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey3[i])+" ");
		System.out.print("\n");
		System.out.print("Plaintext\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData2[i])+" ");
	
		outary2 =  HIGHT_ECB_Encrypt(pbUserKey3,   pbData2,  0, PLAINTEXT_LENGTH );
		pbPlains2 = HIGHT_ECB_Decrypt(pbUserKey3,   outary2,  0, CIPHERTEXT_LENGTH ) ;		
		
		
		System.out.print("\nCiphertext(enc)\t: ");
		for (int i=0; i<CIPHERTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&outary2[i])+" ");
		System.out.print("\n");
		
		System.out.print("Plaintext(dec)\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&pbPlains2[i])+" ");
		System.out.print("\n\n");	
		
		outary2 = null;
		
		
	    /*****************************
	     * �׽�Ʈ ���� 6
	     ****************************/
		

		PLAINTEXT_LENGTH = 8;
		CIPHERTEXT_LENGTH = 16;
		
		System.out.print("\nKey\t\t: ");
		for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey3[i])+" ");
		System.out.print("\n");
		System.out.print("Plaintext\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData2[i])+" ");
	
		outary2 =  HIGHT_ECB_Encrypt(pbUserKey3,   pbData2,  0, PLAINTEXT_LENGTH );
		pbPlains2 = HIGHT_ECB_Decrypt(pbUserKey3,   outary2,  0, CIPHERTEXT_LENGTH ) ;		
		
		System.out.print("\nCiphertext(enc)\t: ");
		for (int i=0; i<CIPHERTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&outary2[i])+" ");
		System.out.print("\n");
		
		System.out.print("Plaintext(dec)\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&pbPlains2[i])+" ");
		System.out.print("\n\n");
		
		outary2 = null;
		
		
		
		
		
		
	    /*****************************
	     * �׽�Ʈ ���� 7
	     ****************************/
		

		PLAINTEXT_LENGTH = 50;
		CIPHERTEXT_LENGTH = 56;
		
		System.out.print("\nKey\t\t: ");
		for (int i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey3[i])+" ");
		System.out.print("\n");
		System.out.print("Plaintext\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData3[i])+" ");
	
		outary2 =  HIGHT_ECB_Encrypt(pbUserKey3,   pbData3,  0, PLAINTEXT_LENGTH );
		pbPlains2 = HIGHT_ECB_Decrypt(pbUserKey3,   outary2,  0, CIPHERTEXT_LENGTH ) ;		
		
		
		System.out.print("\nCiphertext(enc)\t: ");
		for (int i=0; i<CIPHERTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&outary2[i])+" ");
		System.out.print("\n");
		
		System.out.print("Plaintext(dec)\t: ");
		for (int i=0; i<PLAINTEXT_LENGTH; i++)
		System.out.print(Integer.toHexString(0xff&pbPlains2[i])+" ");
		System.out.print("\n\n");	
		
		outary2 = null;
		
		
		
		
		
	    /*****************************************************************************************
	     * ��� 2
	     ******************************************************************************************/
	    
		System.out.print("\n[ Test HIGHT reference code ECB ]  ��� 2"+"\n");
		System.out.print("\n\n");
		
		
		
		/*****************
		 * �׽�Ʈ ���� 1
		 *****************/	 	    
		PLAINTEXT_LENGTH = 8;
		CIPHERTEXT_LENGTH = 16;
		
	
		KISA_HIGHT_INFO info = new KISA_HIGHT_INFO();
		
		HIGHT_ECB_init(info, KISA_ENC_DEC.KISA_ENCRYPT, pbUserKey);
		
		int process_blockLeng = 32;
		int[] outbuf = new int[process_blockLeng];
		int i;
		int[] data;
		byte[] cdata;
		int nRetOutLeng[] = new int[] { 0 };
		int nPaddingLeng[] = new int[] { 0 };
		byte[] pbszPlainText = new byte[process_blockLeng];
		int nPlainTextPadding = (BLOCK_SIZE_HIGHT - (PLAINTEXT_LENGTH)%BLOCK_SIZE_HIGHT);
		
		CIPHERTEXT_LENGTH = PLAINTEXT_LENGTH + nPlainTextPadding;
		
		byte[] pbszCipherText = new byte[PLAINTEXT_LENGTH + nPlainTextPadding];	
		
		for (i = 0; i < PLAINTEXT_LENGTH - process_blockLeng; )
		{
			System.arraycopy(pbData1, i, pbszPlainText, 0, process_blockLeng);
			data = chartoint32_for_HIGHT_ECB(pbszPlainText, process_blockLeng);
			HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
			cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
			System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
			i += nRetOutLeng[0];
		}
		int remainleng = PLAINTEXT_LENGTH % process_blockLeng;
		if (remainleng == 0)
		{
			remainleng = process_blockLeng;
		}
		System.arraycopy(pbData1, i, pbszPlainText, 0, remainleng);
		data = chartoint32_for_HIGHT_ECB(pbszPlainText, remainleng);
		HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
		i += nRetOutLeng[0];
		
		HIGHT_ECB_Close( info, outbuf, 0, nPaddingLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nPaddingLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nPaddingLeng[0]);
		
		System.out.print("Key\t\t: ");
	    for (i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
	    System.out.print("\n");
		System.out.print("Plaintext\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData1[i])+" ");
	    System.out.print("\n");		
		System.out.print("Ciphertext(enc)\t: ");
	    for(i=0; i<CIPHERTEXT_LENGTH; i++)	 	System.out.print(Integer.toHexString(0xff&pbszCipherText[i])+" ");
	    
	    System.out.print("\n");
		
		data = null;
		cdata = null;
		outbuf = null;
		info = null;	
		
		
		/*****************
		 * �׽�Ʈ ���� 1  ��ȣȭ
		 *****************/	 	
		
		
	    byte[] result = new byte[] {0};
		
		info = new KISA_HIGHT_INFO();

		int EncryptedMessage_length = CIPHERTEXT_LENGTH; 
		if (EncryptedMessage_length % BLOCK_SIZE_HIGHT > 0)
		{
			System.out.print("DECRYPT FAIL! ");
		}
		else
		{
			HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_DECRYPT, pbUserKey);
			
			process_blockLeng = 32;
			
			outbuf = new int[process_blockLeng];
			
			byte[] cipherText = new byte[process_blockLeng];
			pbszPlainText = new byte[EncryptedMessage_length];

			for (i = 0; i < EncryptedMessage_length - process_blockLeng; )
			{
				System.arraycopy(pbszCipherText, i, cipherText, 0, process_blockLeng);
				data = chartoint32_for_HIGHT_ECB(cipherText, process_blockLeng);
				HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
				cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
				System.arraycopy(cdata, 0, pbszPlainText, i, nRetOutLeng[0]);
				i += nRetOutLeng[0];
			}
			
			remainleng = EncryptedMessage_length % process_blockLeng;
			if (remainleng == 0)
			{
				remainleng = process_blockLeng;
			}
			
			
			System.arraycopy(pbszCipherText, i, cipherText, 0, remainleng);
			data = chartoint32_for_HIGHT_ECB(cipherText, remainleng);
			HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
			if (HIGHT_ECB_Close( info, outbuf, nRetOutLeng[0], nPaddingLeng ) > 0 )
			{
				cdata = int32tochar_for_HIGHT_ECB( outbuf, remainleng - nPaddingLeng[0] );
				System.arraycopy(cdata, 0, pbszPlainText, i, remainleng - nPaddingLeng[0]);
				int message_length = i + remainleng - nPaddingLeng[0];
				
				result = new byte[message_length];
				System.arraycopy(pbszPlainText, 0, result, 0, message_length);
				data = null;
				cdata = null;
				outbuf = null;
			}
			else
			{
				result = new byte[10];
				System.out.print("DECRYPT FAIL! ");
			}

		}
		
		System.out.print("Plaintext(dec)\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&result[i])+" ");
	    System.out.print("\n\n");	
	    
	    
	    pbszCipherText = null;
	    result = null;
		
		
		
		
		
		
		
		
		
	    
		/*****************
		 * �׽�Ʈ ���� 2
		 *****************/	 	    
		PLAINTEXT_LENGTH = 2;
		CIPHERTEXT_LENGTH = 8;
		

		info = new KISA_HIGHT_INFO();
		
		HIGHT_ECB_init(info, KISA_ENC_DEC.KISA_ENCRYPT, pbUserKey);
		
		process_blockLeng = 32;
		outbuf = new int[process_blockLeng];
		pbszPlainText = new byte[process_blockLeng];
		nPlainTextPadding = (BLOCK_SIZE_HIGHT - (PLAINTEXT_LENGTH)%BLOCK_SIZE_HIGHT);
		
		CIPHERTEXT_LENGTH = PLAINTEXT_LENGTH + nPlainTextPadding;
		
		pbszCipherText = new byte[PLAINTEXT_LENGTH + nPlainTextPadding];	
		
		for (i = 0; i < PLAINTEXT_LENGTH - process_blockLeng; )
		{
			System.arraycopy(pbData2, i, pbszPlainText, 0, process_blockLeng);
			data = chartoint32_for_HIGHT_ECB(pbszPlainText, process_blockLeng);
			HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
			cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
			System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
			i += nRetOutLeng[0];
		}
		remainleng = PLAINTEXT_LENGTH % process_blockLeng;
		if (remainleng == 0)
		{
			remainleng = process_blockLeng;
		}
		System.arraycopy(pbData2, i, pbszPlainText, 0, remainleng);
		data = chartoint32_for_HIGHT_ECB(pbszPlainText, remainleng);
		HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
		i += nRetOutLeng[0];
		
		HIGHT_ECB_Close( info, outbuf, 0, nPaddingLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nPaddingLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nPaddingLeng[0]);
		
		
		
		System.out.print("Key\t\t: ");
	    for (i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
	    System.out.print("\n");
		System.out.print("Plaintext\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData2[i])+" ");
	    System.out.print("\n");		
		System.out.print("Ciphertext(enc)\t: ");
	    for(i=0; i<CIPHERTEXT_LENGTH; i++)	 	System.out.print(Integer.toHexString(0xff&pbszCipherText[i])+" ");
	    
	    System.out.print("\n");
		
		data = null;
		cdata = null;
		outbuf = null;
		info = null;	    
	    
	      	
		/*****************
		 * �׽�Ʈ ���� 2  ��ȣȭ
		 *****************/	 	
		
		
	    result = new byte[] {0};
		
		info = new KISA_HIGHT_INFO();

		EncryptedMessage_length = CIPHERTEXT_LENGTH; 
		if (EncryptedMessage_length % BLOCK_SIZE_HIGHT > 0)
		{
			System.out.print("DECRYPT FAIL! ");
		}
		else
		{
			HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_DECRYPT, pbUserKey);
			
			process_blockLeng = 32;
			
			outbuf = new int[process_blockLeng];
			
			byte[] cipherText = new byte[process_blockLeng];
			pbszPlainText = new byte[EncryptedMessage_length];

			for (i = 0; i < EncryptedMessage_length - process_blockLeng; )
			{
				System.arraycopy(pbszCipherText, i, cipherText, 0, process_blockLeng);
				data = chartoint32_for_HIGHT_ECB(cipherText, process_blockLeng);
				HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
				cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
				System.arraycopy(cdata, 0, pbszPlainText, i, nRetOutLeng[0]);
				i += nRetOutLeng[0];
			}
			
			remainleng = EncryptedMessage_length % process_blockLeng;
			if (remainleng == 0)
			{
				remainleng = process_blockLeng;
			}
			
			
			System.arraycopy(pbszCipherText, i, cipherText, 0, remainleng);
			data = chartoint32_for_HIGHT_ECB(cipherText, remainleng);
			HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
			if (HIGHT_ECB_Close( info, outbuf, nRetOutLeng[0], nPaddingLeng ) > 0 )
			{
				cdata = int32tochar_for_HIGHT_ECB( outbuf, remainleng - nPaddingLeng[0] );
				System.arraycopy(cdata, 0, pbszPlainText, i, remainleng - nPaddingLeng[0]);
				int message_length = i + remainleng - nPaddingLeng[0];
				
				result = new byte[message_length];
				System.arraycopy(pbszPlainText, 0, result, 0, message_length);
				data = null;
				cdata = null;
				outbuf = null;
			}
			else
			{
				result = new byte[10];
				System.out.print("DECRYPT FAIL! ");
			}

		}
		
		System.out.print("Plaintext(dec)\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&result[i])+" ");
	    System.out.print("\n\n");			
	    
	    
	    
	    pbszCipherText = null;
	    result = null;
	    
	    
	    
	    
	    
	    
	    
	    
		/*****************
		 * �׽�Ʈ ���� 3
		 *****************/	 	    
		PLAINTEXT_LENGTH = 10;
		CIPHERTEXT_LENGTH = 16;
		

		info = new KISA_HIGHT_INFO();
		
		HIGHT_ECB_init(info, KISA_ENC_DEC.KISA_ENCRYPT, pbUserKey);
		
		process_blockLeng = 32;
		outbuf = new int[process_blockLeng];
		pbszPlainText = new byte[process_blockLeng];
		nPlainTextPadding = (BLOCK_SIZE_HIGHT - (PLAINTEXT_LENGTH)%BLOCK_SIZE_HIGHT);
		
		CIPHERTEXT_LENGTH = PLAINTEXT_LENGTH + nPlainTextPadding;
		
		pbszCipherText = new byte[PLAINTEXT_LENGTH + nPlainTextPadding];	
		
		for (i = 0; i < PLAINTEXT_LENGTH - process_blockLeng; )
		{
			System.arraycopy(pbData, i, pbszPlainText, 0, process_blockLeng);
			data = chartoint32_for_HIGHT_ECB(pbszPlainText, process_blockLeng);
			HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
			cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
			System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
			i += nRetOutLeng[0];
		}
		remainleng = PLAINTEXT_LENGTH % process_blockLeng;
		if (remainleng == 0)
		{
			remainleng = process_blockLeng;
		}
		System.arraycopy(pbData, i, pbszPlainText, 0, remainleng);
		data = chartoint32_for_HIGHT_ECB(pbszPlainText, remainleng);
		HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
		i += nRetOutLeng[0];
		
		HIGHT_ECB_Close( info, outbuf, 0, nPaddingLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nPaddingLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nPaddingLeng[0]);
		
		
		
		System.out.print("Key\t\t: ");
	    for (i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
	    System.out.print("\n");
		System.out.print("Plaintext\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData[i])+" ");
	    System.out.print("\n");		
		System.out.print("Ciphertext(enc)\t: ");
	    for(i=0; i<CIPHERTEXT_LENGTH; i++)	 	System.out.print(Integer.toHexString(0xff&pbszCipherText[i])+" ");
	    
	    System.out.print("\n");
		
		data = null;
		cdata = null;
		outbuf = null;
		info = null;	    
	    
	      	
		/*****************
		 * �׽�Ʈ ���� 3  ��ȣȭ
		 *****************/	 	
		
		
	    result = new byte[] {0};
		
		info = new KISA_HIGHT_INFO();

		EncryptedMessage_length = CIPHERTEXT_LENGTH; 
		if (EncryptedMessage_length % BLOCK_SIZE_HIGHT > 0)
		{
			System.out.print("DECRYPT FAIL! ");
		}
		else
		{
			HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_DECRYPT, pbUserKey);
			
			process_blockLeng = 32;
			
			outbuf = new int[process_blockLeng];
			
			byte[] cipherText = new byte[process_blockLeng];
			pbszPlainText = new byte[EncryptedMessage_length];

			for (i = 0; i < EncryptedMessage_length - process_blockLeng; )
			{
				System.arraycopy(pbszCipherText, i, cipherText, 0, process_blockLeng);
				data = chartoint32_for_HIGHT_ECB(cipherText, process_blockLeng);
				HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
				cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
				System.arraycopy(cdata, 0, pbszPlainText, i, nRetOutLeng[0]);
				i += nRetOutLeng[0];
			}
			
			remainleng = EncryptedMessage_length % process_blockLeng;
			if (remainleng == 0)
			{
				remainleng = process_blockLeng;
			}
			
			
			System.arraycopy(pbszCipherText, i, cipherText, 0, remainleng);
			data = chartoint32_for_HIGHT_ECB(cipherText, remainleng);
			HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
			if (HIGHT_ECB_Close( info, outbuf, nRetOutLeng[0], nPaddingLeng ) > 0 )
			{
				cdata = int32tochar_for_HIGHT_ECB( outbuf, remainleng - nPaddingLeng[0] );
				System.arraycopy(cdata, 0, pbszPlainText, i, remainleng - nPaddingLeng[0]);
				int message_length = i + remainleng - nPaddingLeng[0];
				
				result = new byte[message_length];
				System.arraycopy(pbszPlainText, 0, result, 0, message_length);
				data = null;
				cdata = null;
				outbuf = null;
			}
			else
			{
				result = new byte[10];
				System.out.print("DECRYPT FAIL! ");
			}

		}
		
		System.out.print("Plaintext(dec)\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&result[i])+" ");
	    System.out.print("\n\n");		    
	    
	    pbszCipherText = null;
	    result = null;
	    
	    
	    
		/*****************
		 * �׽�Ʈ ���� 4
		 *****************/	 	    
		PLAINTEXT_LENGTH = 8;
		CIPHERTEXT_LENGTH = 16;
		

		info = new KISA_HIGHT_INFO();
		
		HIGHT_ECB_init(info, KISA_ENC_DEC.KISA_ENCRYPT, pbUserKey);
		
		process_blockLeng = 32;
		outbuf = new int[process_blockLeng];
		pbszPlainText = new byte[process_blockLeng];
		nPlainTextPadding = (BLOCK_SIZE_HIGHT - (PLAINTEXT_LENGTH)%BLOCK_SIZE_HIGHT);
		
		CIPHERTEXT_LENGTH = PLAINTEXT_LENGTH + nPlainTextPadding;
		
		pbszCipherText = new byte[PLAINTEXT_LENGTH + nPlainTextPadding];	
		
		for (i = 0; i < PLAINTEXT_LENGTH - process_blockLeng; )
		{
			System.arraycopy(pbData, i, pbszPlainText, 0, process_blockLeng);
			data = chartoint32_for_HIGHT_ECB(pbszPlainText, process_blockLeng);
			HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
			cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
			System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
			i += nRetOutLeng[0];
		}
		remainleng = PLAINTEXT_LENGTH % process_blockLeng;
		if (remainleng == 0)
		{
			remainleng = process_blockLeng;
		}
		System.arraycopy(pbData, i, pbszPlainText, 0, remainleng);
		data = chartoint32_for_HIGHT_ECB(pbszPlainText, remainleng);
		HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
		i += nRetOutLeng[0];
		
		HIGHT_ECB_Close( info, outbuf, 0, nPaddingLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nPaddingLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nPaddingLeng[0]);
		
		
		
		System.out.print("Key\t\t: ");
	    for (i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey[i])+" ");
	    System.out.print("\n");
		System.out.print("Plaintext\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData[i])+" ");
	    System.out.print("\n");		
		System.out.print("Ciphertext(enc)\t: ");
	    for(i=0; i<CIPHERTEXT_LENGTH; i++)	 	System.out.print(Integer.toHexString(0xff&pbszCipherText[i])+" ");
	    
	    System.out.print("\n");
		
		data = null;
		cdata = null;
		outbuf = null;
		info = null;	    
	    
	      	
		/*****************
		 * �׽�Ʈ ���� 4  ��ȣȭ
		 *****************/	 	
		
		
	    result = new byte[] {0};
		
		info = new KISA_HIGHT_INFO();

		EncryptedMessage_length = CIPHERTEXT_LENGTH; 
		if (EncryptedMessage_length % BLOCK_SIZE_HIGHT > 0)
		{
			System.out.print("DECRYPT FAIL! ");
		}
		else
		{
			HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_DECRYPT, pbUserKey);
			
			process_blockLeng = 32;
			
			outbuf = new int[process_blockLeng];
			
			byte[] cipherText = new byte[process_blockLeng];
			pbszPlainText = new byte[EncryptedMessage_length];

			for (i = 0; i < EncryptedMessage_length - process_blockLeng; )
			{
				System.arraycopy(pbszCipherText, i, cipherText, 0, process_blockLeng);
				data = chartoint32_for_HIGHT_ECB(cipherText, process_blockLeng);
				HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
				cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
				System.arraycopy(cdata, 0, pbszPlainText, i, nRetOutLeng[0]);
				i += nRetOutLeng[0];
			}
			
			remainleng = EncryptedMessage_length % process_blockLeng;
			if (remainleng == 0)
			{
				remainleng = process_blockLeng;
			}
			
			
			System.arraycopy(pbszCipherText, i, cipherText, 0, remainleng);
			data = chartoint32_for_HIGHT_ECB(cipherText, remainleng);
			HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
			if (HIGHT_ECB_Close( info, outbuf, nRetOutLeng[0], nPaddingLeng ) > 0 )
			{
				cdata = int32tochar_for_HIGHT_ECB( outbuf, remainleng - nPaddingLeng[0] );
				System.arraycopy(cdata, 0, pbszPlainText, i, remainleng - nPaddingLeng[0]);
				int message_length = i + remainleng - nPaddingLeng[0];
				
				result = new byte[message_length];
				System.arraycopy(pbszPlainText, 0, result, 0, message_length);
				data = null;
				cdata = null;
				outbuf = null;
			}
			else
			{
				result = new byte[10];
				System.out.print("DECRYPT FAIL! ");
			}

		}
		
		System.out.print("Plaintext(dec)\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&result[i])+" ");
	    System.out.print("\n\n");		
	    
	    
	    pbszCipherText = null;
	    result = null;
	    
	    
	    
	    
	    
	    
	    
	    
	    
		/*****************
		 * �׽�Ʈ ���� 5
		 *****************/	 	    
		PLAINTEXT_LENGTH = 50;
		CIPHERTEXT_LENGTH = 56;
		

		info = new KISA_HIGHT_INFO();
		
		HIGHT_ECB_init(info, KISA_ENC_DEC.KISA_ENCRYPT, pbUserKey3);
		
		process_blockLeng = 32;
		outbuf = new int[process_blockLeng];
		pbszPlainText = new byte[process_blockLeng];
		nPlainTextPadding = (BLOCK_SIZE_HIGHT - (PLAINTEXT_LENGTH)%BLOCK_SIZE_HIGHT);
		
		CIPHERTEXT_LENGTH = PLAINTEXT_LENGTH + nPlainTextPadding;
		
		pbszCipherText = new byte[PLAINTEXT_LENGTH + nPlainTextPadding];	
		
		for (i = 0; i < PLAINTEXT_LENGTH - process_blockLeng; )
		{
			System.arraycopy(pbData3, i, pbszPlainText, 0, process_blockLeng);
			data = chartoint32_for_HIGHT_ECB(pbszPlainText, process_blockLeng);
			HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
			cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
			System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
			i += nRetOutLeng[0];
		}
		remainleng = PLAINTEXT_LENGTH % process_blockLeng;
		if (remainleng == 0)
		{
			remainleng = process_blockLeng;
		}
		System.arraycopy(pbData3, i, pbszPlainText, 0, remainleng);
		data = chartoint32_for_HIGHT_ECB(pbszPlainText, remainleng);
		HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nRetOutLeng[0]);
		i += nRetOutLeng[0];
		
		HIGHT_ECB_Close( info, outbuf, 0, nPaddingLeng );
		cdata = int32tochar_for_HIGHT_ECB(outbuf, nPaddingLeng[0]);
		System.arraycopy(cdata, 0, pbszCipherText, i, nPaddingLeng[0]);
		
		
		
		System.out.print("Key\t\t: ");
	    for (i=0; i<16; i++)	System.out.print(Integer.toHexString(0xff&pbUserKey3[i])+" ");
	    System.out.print("\n");
		System.out.print("Plaintext\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&pbData3[i])+" ");
	    System.out.print("\n");		
		System.out.print("Ciphertext(enc)\t: ");
	    for(i=0; i<CIPHERTEXT_LENGTH; i++)	 	System.out.print(Integer.toHexString(0xff&pbszCipherText[i])+" ");
	    
	    System.out.print("\n");
		
		data = null;
		cdata = null;
		outbuf = null;
		info = null;	    
	    
	      	
		/*****************
		 * �׽�Ʈ ���� 5  ��ȣȭ
		 *****************/	 	
		
		
	    result = new byte[] {0};
		
		info = new KISA_HIGHT_INFO();

		EncryptedMessage_length = CIPHERTEXT_LENGTH; 
		if (EncryptedMessage_length % BLOCK_SIZE_HIGHT > 0)
		{
			System.out.print("DECRYPT FAIL! ");
		}
		else
		{
			HIGHT_ECB_init( info, KISA_ENC_DEC.KISA_DECRYPT, pbUserKey3);
			
			process_blockLeng = 32;
			
			outbuf = new int[process_blockLeng];
			
			byte[] cipherText = new byte[process_blockLeng];
			pbszPlainText = new byte[EncryptedMessage_length];

			for (i = 0; i < EncryptedMessage_length - process_blockLeng; )
			{
				System.arraycopy(pbszCipherText, i, cipherText, 0, process_blockLeng);
				data = chartoint32_for_HIGHT_ECB(cipherText, process_blockLeng);
				HIGHT_ECB_Process( info, data, process_blockLeng, outbuf, nRetOutLeng );
				cdata = int32tochar_for_HIGHT_ECB(outbuf, nRetOutLeng[0]);
				System.arraycopy(cdata, 0, pbszPlainText, i, nRetOutLeng[0]);
				i += nRetOutLeng[0];
			}
			
			remainleng = EncryptedMessage_length % process_blockLeng;
			if (remainleng == 0)
			{
				remainleng = process_blockLeng;
			}
			
			
			System.arraycopy(pbszCipherText, i, cipherText, 0, remainleng);
			data = chartoint32_for_HIGHT_ECB(cipherText, remainleng);
			HIGHT_ECB_Process( info, data, remainleng, outbuf, nRetOutLeng );
			if (HIGHT_ECB_Close( info, outbuf, nRetOutLeng[0], nPaddingLeng ) > 0 )
			{
				cdata = int32tochar_for_HIGHT_ECB( outbuf, remainleng - nPaddingLeng[0] );
				System.arraycopy(cdata, 0, pbszPlainText, i, remainleng - nPaddingLeng[0]);
				int message_length = i + remainleng - nPaddingLeng[0];
				
				result = new byte[message_length];
				System.arraycopy(pbszPlainText, 0, result, 0, message_length);
				data = null;
				cdata = null;
				outbuf = null;
			}
			else
			{
				result = new byte[10];
				System.out.print("DECRYPT FAIL! ");
			}

		}
		
		System.out.print("Plaintext(dec)\t: ");
	    for (i=0; i<PLAINTEXT_LENGTH; i++)	System.out.print(Integer.toHexString(0xff&result[i])+" ");
	    System.out.print("\n\n");
	    
	    
	    pbszCipherText = null;
	    result = null;
	    
	
	    

	}	
	    
	  	
	
}
