package kr.re.nsr.crypto.mac;

import java.util.Arrays;

import kr.re.nsr.crypto.Hash;
import kr.re.nsr.crypto.Mac;

/**
 * HMAC 구현
 */
public class HMac extends Mac {

	private static final byte IPAD = 0x36;
	private static final byte OPAD = 0x5c;

	private int blocksize;
	private Hash digest;

	private byte[] i_key_pad;
	private byte[] o_key_pad;

	/**
	 * 생성자
	 * 
	 * @param md
	 *            MessageDigest 객체
	 */
	public HMac(Hash md) {
		if (md == null) {
			throw new IllegalArgumentException("md should not be null");
		}

		digest = md.newInstance();
		blocksize = digest.getBlockSize();

		i_key_pad = new byte[blocksize];
		o_key_pad = new byte[blocksize];
	}

	/**
	 * 내부 상태 초기화
	 * 
	 * @param key
	 *            비밀키
	 */
	public void init(byte[] key) {

		if (key == null) {
			throw new IllegalArgumentException("key should not be null");
		}

		if (key.length > blocksize) {
			digest.reset();
			key = digest.doFinal(key);
		}

		Arrays.fill(i_key_pad, IPAD);
		Arrays.fill(o_key_pad, OPAD);
		for (int i = 0; i < key.length; ++i) {
			i_key_pad[i] ^= (byte) (key[i]);
			o_key_pad[i] ^= (byte) (key[i]);
		}

		reset();
	}

	/**
	 * 해시 함수를 초기화하고 i_key_pad 를 hash 함수에 넣어둔다
	 */
	public void reset() {
		digest.reset();
		digest.update(i_key_pad);
	}

	/**
	 * MAC을 계산할 메시지를 hash 함수에 넣는다
	 */
	public void update(byte[] msg) {
		if (msg == null) {
			return;
		}

		digest.update(msg);
	}

	/**
	 * H(i_key_pad || msg) 를 계산하고, H(o_key_pad || H(i_key_pad || msg)) 를 계산한다.
	 */
	public byte[] doFinal() {
		byte[] result = digest.doFinal();
		digest.reset();
		digest.update(o_key_pad);
		result = digest.doFinal(result);

		reset();
		return result;
	}

	public static byte[] digest(Hash.Algorithm algorithm, byte[] key, byte[] msg) {
		Hash hash = Hash.getInstance(algorithm);
		HMac hmac = new HMac(hash);
		hmac.init(key);
		return hmac.doFinal(msg);
	}
}
