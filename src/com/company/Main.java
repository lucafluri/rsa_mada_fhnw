package com.company;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;
import java.io.*;
import java.util.stream.Collectors;


public class Main {


    public static void main(String[] args) throws IOException {


        //Part I of Assignment
        RSAPublicKey publicKey = generatePublicKey(1024);
        RSAPrivateKey privateKey = generatePrivateKey(publicKey);
        publicKey.saveKey(); //
        privateKey.saveKey();


        //Part II of Assignment
        encryptText(readPublicKey());

        //part III and IV of Assignment
        decryptCipher(readPrivateKey());

    }

    /**
     * Generates RSA Public Key
     * @param bitLength BitLength of p and q
     * @return RSA Public Key
     */
    public static RSAPublicKey generatePublicKey(int bitLength){

        print("Generating Public Key");
        //PUBLIC KEY

        //Calc p, q and then n
        BigInteger p = BigInteger.probablePrime(bitLength, new Random());
        BigInteger q = BigInteger.probablePrime(bitLength, new Random());

        while(p.equals(q)){
            System.out.println("LUCKY!!");
            q = BigInteger.probablePrime(bitLength, new Random());
        }
        //Calc n
        BigInteger n = p.multiply(q);
        //Calc Phi(n)
        BigInteger phin = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        //Calc e by searching for a suitable prime that is smaller that phi(n).
        //Since all primes smaller than phi(n) are in Z_phi(n)^*
        //Just a shortcut
        BigInteger e = BigInteger.probablePrime(bitLength, new Random());
        while(e.compareTo(phin)>= 0){
            e = BigInteger.probablePrime(bitLength, new Random());
        }

        //System.out.println("e: " + e);

        return new RSAPublicKey(n, e, phin);
    }

    /**
     * Generates Private Key from Public Key using the extended euclidian algorithm
     * @param publicKey Public Key which has phin != null
     * @return RSAPrivateKey Object
     */
    public static RSAPrivateKey generatePrivateKey(RSAPublicKey publicKey){
        print("Generating Private Key");
        //PRIVATE KEY
        if(publicKey.getPhiN()!=null) {
            //Calcs d using the extended euclidian algorithm
            BigInteger d = euclid(publicKey.getPhiN(), publicKey.getE())[1]; //returns [gcd, y0] y0 of which is d
            //System.out.println("d: " + d);

            return new RSAPrivateKey(publicKey.getN(), d);
        }else {
            return null;
        }
    }



    /**
     * Reads Public Key from "pk.txt"
     * @return RSAPublicKey Instance
     * @throws IOException due to reading access
     */
    public static RSAPublicKey readPublicKey() throws IOException{
        print("Reading Public Key");
        //Read public Key from file
        String[] read = Files.lines(Paths.get("pk.txt")).collect(Collectors.toList()).get(0).split(",");

        //Eliminates ( and ) from Strings
        BigInteger n = new BigInteger(read[0].substring(1));
        BigInteger e = new BigInteger(read[1].substring(0, read[1].length()-1));

        return new RSAPublicKey(n, e);
    }

    /**
     * Reads Private Keys from "sk.txt"
     * @return RSAPrivateKey Instance
     * @throws IOException due to reading access
     */
    public static RSAPrivateKey readPrivateKey() throws IOException{
        print("Reading Private Key");
        //Read public Key
        String[] read = Files.lines(Paths.get("sk.txt")).collect(Collectors.toList()).get(0).split(",");

        //Eliminates ( and ) from Strings
        BigInteger n = new BigInteger(read[0].substring(1));
        BigInteger d = new BigInteger(read[1].substring(0, read[1].length()-1));

        return new RSAPrivateKey(n, d);
    }



    /**
     * Encrypts by using fast exponentiation algorithm
     * @param x number to encrypt
     * @param e exponent e from RSAPublicKey
     * @param n n from RSA Key Pair
     * @return y = encrypted number x
     */
    public static BigInteger encrypt(BigInteger x, BigInteger e, BigInteger n){
        return fastExp(x, e, n);
    }

    /**
     * Decrypts RSA by using fast exponentiation algorithm
     * @param y Number to decrypt
     * @param d d from RSAPrivateKey
     * @param n n from Key Pair
     * @return x = Decrypted Number
     */
    public static BigInteger decrypt(BigInteger y, BigInteger d, BigInteger n){
        return fastExp(y, d, n);
    }



    /**
     * Encrypts text.txt using a RSAPublicKey
     * @param publicKey Public Key to encrypt with
     * @throws IOException due to File Access
     */
    public static void encryptText(RSAPublicKey publicKey) throws IOException{
        print("Encrypting Text");
        //READ text.txt
        byte[] bytes = Files.readAllBytes(Paths.get("text.txt"));
        String toSave = "";

        //Encrypts every byte and adds the encrypted text to cipher.txt
        for(int i = 0; i<bytes.length; i++) {
            toSave += encrypt(BigInteger.valueOf((int) bytes[i]), publicKey.getE(), publicKey.getN()) + ",";
        }

        //Saves cipher.txt
        Files.write(Paths.get("cipher.txt"), toSave.getBytes());

    }

    /**
     * Decrypts cipher.txt using a RSAPrivateKey
     * @param privateKey Private Key to decrypt with
     * @throws IOException due to file access
     */
    public static void decryptCipher(RSAPrivateKey privateKey) throws IOException{
        print("Decrypting Cipher...");

        //Reads cipher.txt and splits it into seperate strings
        String[] toDecrypt = Files.lines(Paths.get("cipher.txt")).collect(Collectors.toList()).get(0).split(",");
        String toSave = "";
        //Every String is converted into BigInteger and then decrypted with PrivateKey
        for(String string : toDecrypt){
            BigInteger decrypted = decrypt(new BigInteger(string), privateKey.getD(), privateKey.getN());

            //Decrypted result is saved as char to temp String
            toSave += (char)decrypted.intValue();
        }
        //Decrypted cipher.txt is written to tex-d.txt
        Files.write(Paths.get("text-d.txt"), toSave.getBytes());
    }




    /**
     * Implementation of the extended euclidian alogorithm
     * @param a a' of algorithm
     * @param b b' of algorithm
     * @return array with gcd and y0 [gcd, y0]
     */
    public static BigInteger[] euclid (BigInteger a, BigInteger b){
        BigInteger _a = a;
        BigInteger _b = b;
        BigInteger x0 = BigInteger.ONE;
        BigInteger y0 = BigInteger.ZERO;
        BigInteger x1 = BigInteger.ZERO;
        BigInteger y1 = BigInteger.ONE;
        BigInteger q;
        BigInteger r;
        BigInteger _x0, _y0;


        while(!_b.equals(BigInteger.ZERO)){
            q = _a.divide(_b);
            r = _a.mod(_b);
            _a = _b;
            _b = r;
            _x0 = x0;
            _y0 = y0;
            x0 = x1;
            y0 = y1;
            x1 = _x0.subtract(q.multiply(x1));
            y1 = _y0.subtract(q.multiply(y1));

        }
        BigInteger result = x0.multiply(a).add(y0.multiply(b));

        if(y0.compareTo(BigInteger.ZERO)<0){
            y0 = y0.add(a); //Adjust y0 to be a positive number -> y0=y0+phi(n) if y0 is negative
        }

        return new BigInteger[]{result, y0};
    }

    /**
     * Implementation of the fast expnentiation algorithm
     * @param x BigInteger Base
     * @param e BigInteger Exponent
     * @param m BigInteger Modulo
     * @return BigInteger Result of Calculation
     */
    public static BigInteger fastExp(BigInteger x, BigInteger e, BigInteger m){
        int i = e.bitLength();
        BigInteger h = BigInteger.ONE;
        BigInteger k = x;

        while(i>=0){
            if(e.testBit(e.bitLength()-i)){
                h = h.multiply(k).mod(m);
            }
            k=k.pow(2).mod(m);
            i--;
        }

        return h;
    }

    /**
     * Shortcut for simple Text Printing
     * @param s String Text to print
     */
    public static void print(String s){
        System.out.println(s);
    }
}
