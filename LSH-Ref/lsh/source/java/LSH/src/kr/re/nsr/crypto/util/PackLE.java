package kr.re.nsr.crypto.util;

/**
 * 바이트 배열을 리틀 엔디안 형식의 정수로 변환하기 위한 도구
 */
public class PackLE {

	/**
	 * 바이트 배열을 unsigned integer 로 변환
	 * 
	 * @param in
	 *            변환할 바이트 배열
	 * @param offset
	 *            시작 오프셋
	 * @return
	 */
	public static int toU32(byte[] in, int offset) {

		int result = (in[offset] & 0xff);
		result |= (in[++offset] & 0xff) << 8;
		result |= (in[++offset] & 0xff) << 16;
		result |= (in[++offset] & 0xff) << 24;

		return result;
	}

	/**
	 * 바이트 배열을 unsigned integer 배열로 변환
	 * 
	 * @param in
	 *            변환할 바이트 배열
	 * @param inOff
	 *            바이트 배열의 시작 오프셋
	 * @param out
	 *            unsigned integer 배열
	 * @param outOff
	 *            unsigned integer 배열의 시작 오프셋
	 * @param length
	 *            변환할 unsigned integer 의 길이
	 */
	public static void toU32(byte[] in, int inOff, int[] out, int outOff, int length) {

		for (int idx = outOff; idx < outOff + length; ++idx, ++inOff) {
			out[idx] = in[inOff] & 0xff;
			out[idx] |= (in[++inOff] & 0xff) << 8;
			out[idx] |= (in[++inOff] & 0xff) << 16;
			out[idx] |= (in[++inOff] & 0xff) << 24;
		}

	}

	/**
	 * 바이트 배열을 unsigned long 으로 변환
	 * 
	 * @param in
	 *            변환할 바이트 배열
	 * @param offset
	 *            시작 오프셋
	 * @return
	 */
	public static long toU64(byte[] in, int offset) {

		long result = (in[offset] & 0xff);
		result |= (long) (in[++offset] & 0xff) << 8;
		result |= (long) (in[++offset] & 0xff) << 16;
		result |= (long) (in[++offset] & 0xff) << 24;
		result |= (long) (in[++offset] & 0xff) << 32;
		result |= (long) (in[++offset] & 0xff) << 40;
		result |= (long) (in[++offset] & 0xff) << 48;
		result |= (long) (in[++offset] & 0xff) << 56;

		return result;
	}

	/**
	 * 바이트 배열을 unsigned long 배열로 변환
	 * 
	 * @param in
	 *            변환할 바이트 배열
	 * @param inOff
	 *            바이트 배열의 시작 오프셋
	 * @param out
	 *            unsigned long 배열
	 * @param outOff
	 *            unsigned long 배열의 시작 오프셋
	 * @param length
	 *            변환할 unsigned long 의 길이
	 */
	public static void toU64(byte[] in, int inOff, long[] out, int outOff, int length) {

		for (int idx = outOff; idx < outOff + length; ++idx, ++inOff) {
			out[idx] = in[inOff] & 0xff;
			out[idx] |= (long) (in[++inOff] & 0xff) << 8;
			out[idx] |= (long) (in[++inOff] & 0xff) << 16;
			out[idx] |= (long) (in[++inOff] & 0xff) << 24;
			out[idx] |= (long) (in[++inOff] & 0xff) << 32;
			out[idx] |= (long) (in[++inOff] & 0xff) << 40;
			out[idx] |= (long) (in[++inOff] & 0xff) << 48;
			out[idx] |= (long) (in[++inOff] & 0xff) << 56;
		}

	}
}
