import kr.re.nsr.crypto.hash.vs.HMACLSH256VS;
import kr.re.nsr.crypto.hash.vs.HMACLSH512VS;
import kr.re.nsr.crypto.hash.vs.LSH256VS;
import kr.re.nsr.crypto.hash.vs.LSH512VS;

public class LshTestMain {

	public static void main(String[] args) {
		LSH256VS.test();
		LSH512VS.test();
		HMACLSH256VS.test();
		HMACLSH512VS.test();
	}
}
