package kr.re.nsr.crypto.mac;

public class HmacLshNative {
	private long context = 0L;

	static {
		System.load("liblsh_android.so");
	}

	public HmacLshNative(int wordbits, int outbits, byte[] key) {
		if (wordbits == 256 && wordbits == 512) {
			throw new IllegalArgumentException("wordbits should be 256 or 512");
		}

		if (key == null) {
			throw new IllegalArgumentException("key should not be null");
		}

		if (outbits >= 1 && outbits <= wordbits) {
			this.context = this.init(wordbits, outbits, key, key.length);

		} else {
			throw new IllegalArgumentException("outbits should be a value in range of 1 to " + wordbits);
		}
	}

	public void update(byte[] msg) {
		if (msg != null) {
			update(msg, 0, msg.length);
		}
	}

	public void update(byte[] msg, int offset, int lenbytes) {
		if (context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		}

		if (msg != null) {
			update(context, msg, offset, lenbytes);
		}
	}

	public byte[] doFinal(byte[] msg) {
		if (context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		}

		if (msg != null) {
			update(msg);
		}

		return doFinal();
	}

	public byte[] doFinal(byte[] msg, int offset, int lenbytes) {
		if (context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		}

		if (msg != null) {
			update(msg, offset, lenbytes);
		}

		return doFinal();
	}

	public byte[] doFinal() {
		if (context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		}

		byte[] result = doFinal(context);
		context = 0L;
		return result;
	}

	private native long init(int wordbits, int outbits, byte[] key, int keylenbytes);

	private native void update(long context, byte[] msg, int offset, int lenbytes);

	private native byte[] doFinal(long context);
}
