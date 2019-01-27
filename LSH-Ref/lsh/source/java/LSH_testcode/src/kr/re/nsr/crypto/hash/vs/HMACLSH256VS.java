package kr.re.nsr.crypto.hash.vs;

import java.util.Arrays;

import kr.re.nsr.crypto.Hash;
import kr.re.nsr.crypto.Mac;

public class HMACLSH256VS {

	//@formatter:off
	static final byte[][] key = {
			"key".getBytes(),
			new byte[1024],
		};
	
	static final byte[] data = "A quick brown fox jumps over the lazy dog".getBytes();
	
	static final byte[][] result = {
			{(byte) 0x01, (byte) 0x28, (byte) 0xd9, (byte) 0xd5, (byte) 0xaf, (byte) 0xbc, (byte) 0x27, (byte) 0xd4, (byte) 0x03, (byte) 0x46, (byte) 0x9f, (byte) 0xcc, (byte) 0x02, (byte) 0xaf, (byte) 0xa5, (byte) 0xb5, (byte) 0xb0, (byte) 0xcc, (byte) 0x34, (byte) 0xc0, (byte) 0x20, (byte) 0x0a, (byte) 0xd6, (byte) 0xe8, (byte) 0x1e, (byte) 0xd9, (byte) 0x4c, (byte) 0x8d, (byte) 0x52, (byte) 0x41, (byte) 0x97, (byte) 0x83, },
			{(byte) 0xe0, (byte) 0x0e, (byte) 0x60, (byte) 0x56, (byte) 0x65, (byte) 0xaa, (byte) 0x03, (byte) 0x47, (byte) 0x19, (byte) 0x71, (byte) 0x10, (byte) 0xce, (byte) 0xb9, (byte) 0x85, (byte) 0x4a, (byte) 0x2d, (byte) 0x4b, (byte) 0x41, (byte) 0x27, (byte) 0x62, (byte) 0x07, (byte) 0xec, (byte) 0xaa, (byte) 0xfc, (byte) 0x67, (byte) 0xf6, (byte) 0x7c, (byte) 0xe5, (byte) 0x44, (byte) 0x32, (byte) 0x87, (byte) 0xa1, },
		};
	//@formatter:on

	public static void test() {
		for (int i = 0; i < key.length; ++i) {
			test(key[i], data, result[i]);
		}
	}

	public static void test(byte[] key, byte[] msg, byte[] ref) {
		Mac mac = Mac.getInstance(Hash.Algorithm.LSH256_256);
		mac.init(key);
		byte[] hmac = mac.doFinal(msg);
		System.out.printf("HMAC-LSH256-TEST: %s\n", Arrays.equals(hmac, ref));
	}

}
