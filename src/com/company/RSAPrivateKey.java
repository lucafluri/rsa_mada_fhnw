package com.company;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class RSAPrivateKey {
    private BigInteger n;
    private BigInteger d;

    public RSAPrivateKey(BigInteger n, BigInteger d){
        this.n = n;
        this.d = d;
    }

    public BigInteger getN(){
        return n;
    }

    public BigInteger getD(){
        return d;
    }

    /**
     * Writes the Private Key to file -> sk.txt
     * @throws IOException
     */
    public void saveKey() throws IOException {
        Files.write(Paths.get("sk.txt"), ("(" + n + "," + d + ")").getBytes());
    }
}
