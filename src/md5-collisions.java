import java.util.ArrayList;

class MD5Collisions {
    public static void main(String[] args) {
        md5 MD5 = new md5(); // new MD5 class object defined
        MD5.SetPlaintext("A four-word buffer (A,B,C,D) is used to compute the message digest.\r\n" + 
        		"   Here each of A, B, C, D is a 32-bit register. These registers are\r\n" + 
        		"   initialized to the following values in hexadecimal, low-order bytes\r\n" + 
        		"   first):"); // MD5 input ciphertext defined
        
        // MD5 hashing steps (to be encapsulated into a single method in MD5 class once ready)
        String binaryString = MD5.TextToBinaryString(MD5.TextToBinary(MD5.GetPlaintext()));
        int[] binaryArray = MD5.BinaryArray(binaryString);
        ArrayList<Integer> padded = MD5.md5Step1AppendBits(binaryArray);
        ArrayList<Integer> paddedAppended = MD5.md5Step2AppendLength(padded);
        
        MD5.md5Step3Process16bitWordBlocks(paddedAppended);
        String output = MD5.MessageDigestString();
        System.out.println(output);
    }
}