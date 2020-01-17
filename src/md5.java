import java.math.*;
import java.lang.Number.*;
import java.lang.*;
import java.util.*;
class md5 {
	
	public String plaintext;
	public String ciphertext;
	
	public String MDBufferA = "00000001001000110100010101100111";
	public String MDBufferB = "10001001101010111100110111101111";
	public String MDBufferC = "11111110110111001011101010011000";
	public String MDBufferD = "01110110010101000011001000010000";
	
	public int[] AA;
	public int[] BB;
	public int[] CC;
	public int[] DD;

	public int[] X;
	public int[] Y;
	public int[] Z;
	
	public int[][] InitialiseFunctionT() {
		MD5FunctionT functionT = new MD5FunctionT();
		int[][] functionTMatrix = new int[functionT.SeedData().size()][32];
		for(int i = 0; i < functionT.SeedData().size(); i++) {
			functionTMatrix[i] = BinaryArray(functionT.SeedData().get(i));
		}
		return functionTMatrix;
	}

	public void SetPlaintext(String inputstring) {
		this.plaintext = inputstring;
	}
	
	public String GetPlaintext() {
		return this.plaintext;
	}
	
	public void SetCiphertext(String inputstring) {
		this.ciphertext = inputstring;
	}
	
	public String GetCiphertext() {
		return this.ciphertext;
	}
	
	// method to convert an input string into a binary representation using BigInteger format
	public BigInteger TextToBinary(String inputstring) {
		BigInteger binaryInt = new BigInteger(inputstring.getBytes());
		return binaryInt;
	}
	
	// method to covert a binary value in BigInteger form into a string representation (e.g, 1010101 -> '1010101')
	public String TextToBinaryString(BigInteger inputinteger) {
		String binaryString = inputinteger.toString(2);
		return binaryString;
	}

	// method to convert a binary value in string representation to an int array format (e.g, '1010101' -> [1,0,1,0,1,0,1]
	public int[] BinaryArray(String inputstring) {
	    int[] binaryArray = new int[inputstring.length()];
	    String[] inputstringelement = inputstring.split("");
	    for (int i = 0; i < binaryArray.length; i++) {
	        binaryArray[i] = Integer.parseInt(inputstringelement[i]);
	    }
	    return binaryArray;
	}

	public int[] BinaryListToBinaryArray(ArrayList<Integer> inputarray) {
		int[] outputArray = new int[inputarray.size()];
		for(int i = 0; i < inputarray.size(); i++) {
			outputArray[i] = inputarray.get(i);
		}
		return outputArray;
	}
	
	public int logicalOR(int a, int b) {
		if(a == 0 && b == 0) {
			return 0;
		} else {
			return a;
		}
	}

	public int logicalNOT(int a) {
		if(a == 0) {
			return a;
		} else {
			return 0;
		}
	}

	public int logicalXOR(int a, int b) {
		if(a == b) {
			return 0;
		} else {
			if(a == 0) {
				return b;
			} else {
				return a;
			}
		}
	}
	
	public int[] arrayAddition(int[] a, int[] b) {
		int[] result = new int[a.length];
		for(int i = 0; i < a.length; i++) {
			result[i] = a[i] + b[i];
		}
		return result;
	}
	
	public ArrayList<Integer> BinaryArrayToBinaryList(int[] inputarray) {
		ArrayList<Integer> outputArrayList = new ArrayList<Integer>();
		for(int i = 0; i < inputarray.length; i++) {
			outputArrayList.add(inputarray[i]);
		}
		return outputArrayList;
	}
	
	// method to conduct step 1 of MD5 hash: appending padded bits to that message length is congruent to 448, modulo 512. First
	// bit of padding is 1, all subsequent padded bits are 0
	public ArrayList<Integer> md5Step1AppendBits(int[] inputarray) {
		int arrayLength = inputarray.length;
		int padValue = 0;
		ArrayList<Integer> paddedArray = new ArrayList<Integer>();
		if(arrayLength%512 < 448) {
			padValue = Math.abs(448 - arrayLength%512);
		} else {
			padValue = 448 + Math.abs(448 - arrayLength%512);
		}
		for(int i = 0; i < arrayLength; i ++) {
			paddedArray.add(inputarray[i]);
		}
		for(int i = 0; i < padValue; i++) {
			if(i < 1) {
				paddedArray.add(1);
			} else {
				paddedArray.add(0);
			}
		}
		return paddedArray;
	}

	// need to convert bit size into 64 bit representation
	public ArrayList<Integer> md5Step2AppendLength(ArrayList<Integer> inputarraylist) {
		ArrayList<Integer> paddedArrayLengthAppended = (ArrayList<Integer>) inputarraylist.clone();
		int arrayLength = inputarraylist.size();
		String[] arrayLengthBinary = Integer.toBinaryString(arrayLength).split("");
		ArrayList<Integer> arrayLengthBinary64bit = new ArrayList<Integer>();
		for(int i = 0; i < 64; i++) {
			if(i < (64-arrayLengthBinary.length)) {
				arrayLengthBinary64bit.add(0);
			} else {
				arrayLengthBinary64bit.add(Integer.parseInt(arrayLengthBinary[i - 64 + arrayLengthBinary.length]));
			}
		}
		for(int i = 0; i < arrayLengthBinary64bit.size(); i++) {
			paddedArrayLengthAppended.add(arrayLengthBinary64bit.get(i));
		}
		return paddedArrayLengthAppended;
	}
	
	// unit tests for each of these
	public int[] md5FunctionF(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalOR((X[i]*Y[i]),(logicalNOT(X[i])))*Z[i];
		}
		return result;
	}
	
	public int md5FunctionF(int X, int Y, int Z) {
		int result = logicalOR((X*Y),(logicalNOT(X)))*Z;
		return result;
	}
	
	public int[] md5FunctionG(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalOR((X[i]*Z[i]),Y[i])*logicalNOT(Z[i]);
		}
		return result;
	}

	public int[] md5FunctionH(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalXOR(logicalXOR(X[i],Y[i]),Z[i]);
		}
		return result;
	}
	
	public int[] md5FunctionI(int[] X, int[] Y, int[] Z) {
		int[] result = new int[X.length];
		for(int i = 0; i < X.length; i++) {
			result[i] = logicalXOR(Y[i],logicalOR(X[i],logicalNOT(Z[i])));
		}
		return result;
	}
	
	public int[] AddArray(int[] x, int[] y) {
		int[] result = new int[x.length];
		for(int i = 0; i < x.length; i++) {
			result[i] = x[i] + y[i];
		}
		return result;
	}
	
	public int[] AddArray(int[] x, int[] y, int[] z, int[] xx) {
		int[] result = new int[x.length];
		for(int i = 0; i < x.length; i++) {
			result[i] = x[i] + y[i] + z[i] + xx[i];
		}
		return result;
	}

	public long[] md5FunctionT() {
		long k = 4294967296L;
		long[] T = new long[64];
		for(double i = 0; i < 64; i++) {
			T[(int) i] = (long) (k*Math.abs(Math.sin(i)));
		}
		return T;
	}

	public int[] BitShiftLeft(int[] inputarray, int shiftvalue) {
		int[] outputArray = new int[inputarray.length];
		for(int i = 0; i < inputarray.length - shiftvalue; i++) {
			outputArray[i] = inputarray[i + shiftvalue];
		}
		for(int i = 0; i < shiftvalue; i++) {
			outputArray[inputarray.length - shiftvalue] = 0;
		}
		return outputArray;
	}
	
	public ArrayList<Integer> md5Step3Process16bitWordBlocks(ArrayList<Integer> inputarraylist) {
		/* Process each 16-word block. */
		this.X = new int[32];
		this.Y = new int[32];
		this.Z = new int[32];
		int[] tempA = BinaryArray(this.MDBufferA);
		int[] tempB = BinaryArray(this.MDBufferB);
		int[] tempC = BinaryArray(this.MDBufferC);
		int[] tempD = BinaryArray(this.MDBufferD);
		int[][] functionT = InitialiseFunctionT();
		
		for(int i = 0; i < (inputarraylist.size()/16 - 1); i++) {
			/* Copy block i into X. */
		     for(int j = 0; j < 32; j++) {
		    	 X[j] = inputarraylist.get((i*16) + j);
		     } /* end of loop on j */
		     
		     /* Save A as AA, B as BB, C as CC, and D as DD. */
		     this.AA = BinaryArray(this.MDBufferA);
		     this.BB = BinaryArray(this.MDBufferA);
		     this.CC = BinaryArray(this.MDBufferA);
		     this.DD = BinaryArray(this.MDBufferA);
		     
		     /* Round 1. */
		     /* Let [abcd k s i] denote the operation
		          a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
		     /* Do the following 16 operations. */
		     
		     this.AA = this.BB + BitShiftLeft((AddArray(this.AA,md5FunctionF(this.BB,this.CC,this.DD),X[0],functionT[1])),7);
		     
		     
		     
		     
		     this.BB = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[1] + ((int) this.T[2]),12));
		     this.CC = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[2] + ((int) this.T[3]),17));
		     this.DD = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[3] + ((int) this.T[4]),22));
		     this.AA = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[4] + ((int) this.T[5]),7));
		     this.BB = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[5] + ((int) this.T[6]),12));
		     this.CC = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[6] + ((int) this.T[7]),17));
		     this.DD = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[7] + ((int) this.T[8]),22));
		     this.AA = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[8] + ((int) this.T[9]),7));
		     this.BB = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[9] + ((int) this.T[10]),12));
		     this.CC = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[10] + ((int) this.T[11]),17));
		     this.DD = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[11] + ((int) this.T[12]),22));
		     this.AA = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[12] + ((int) this.T[13]),7));
		     this.BB = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[13] + ((int) this.T[14]),12));
		     this.CC = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[14] + ((int) this.T[15]),17));
		     this.DD = this.BB + (BitShiftLeft((this.AA + md5FunctionF(this.BB,this.CC,this.DD)) + X[15] + ((int) this.T[16]),22));
		     
		}
		ArrayList<Integer> test = new ArrayList<Integer>();
		return test;
	}

}