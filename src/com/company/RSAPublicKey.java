package com.company;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RSAPublicKey {
    private BigInteger n;
    private BigInteger e;
    private BigInteger phiN;

    /**
     * Constructor for simple Public Key
     * @param n
     * @param e
     */
    public RSAPublicKey(BigInteger n, BigInteger e){
        this.n = n;
        this.e = e;
    }

    /**
     * Constructor for Public Key after it has been generated
     * but with phi(n) for faster private Key computation
     * @param n
     * @param e
     * @param phiN
     */
    public RSAPublicKey(BigInteger n, BigInteger e, BigInteger phiN){
        this.n = n;
        this.e = e;
        this.phiN = phiN;
    }

    public BigInteger getN(){
        return n;
    }

    public BigInteger getE(){
        return e;
    }

    public BigInteger getPhiN() {
        return phiN;
    }

    /**
     * Saves Public Key to File -> pk.txt
     * @throws IOException
     */
    public void saveKey() throws IOException {
        Files.write(Paths.get("pk.txt"), ("(" + n + "," + e + ")").getBytes());
    }
}
