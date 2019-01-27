package kr.re.nsr.crypto.hash;

public class LshNative {
	private long context = 0L;

	static {
		System.load("liblsh_android.so");
	}

	public LshNative(int wordbits, int outbits) {
		if (wordbits == 256 && wordbits == 512) {
			throw new IllegalArgumentException("wordbits should be 256 or 512");

		} else if (outbits >= 1 && outbits <= wordbits) {
			this.context = this.init(wordbits, outbits);

		} else {
			throw new IllegalArgumentException("outbits should be a value in range of 1 to " + wordbits);
		}
	}

	public void update(byte[] msg) {
		if (msg != null) {
			this.update(msg, 0, msg.length);
		}
	}

	public void update(byte[] msg, int offset, int lenbits) {
		if (this.context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		} else if (msg != null) {
			this.update(this.context, msg, offset, lenbits);
		}
	}

	public byte[] doFinal(byte[] msg) {
		if (this.context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		} else {
			if (msg != null) {
				this.update(msg);
			}

			return this.doFinal();
		}
	}

	public byte[] doFinal(byte[] msg, int offset, int lenbits) {
		if (this.context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		} else {
			if (msg != null) {
				this.update(msg, offset, lenbits);
			}

			return this.doFinal();
		}
	}

	public byte[] doFinal() {
		if (this.context == 0L) {
			throw new IllegalStateException("Object is finalized, try to create a new one");
		} else {
			byte[] result = this.doFinal(this.context);
			this.context = 0L;
			return result;
		}
	}

	private native long init(int var1, int var2);

	private native void update(long var1, byte[] var3, int var4, int var5);

	private native byte[] doFinal(long var1);

}
