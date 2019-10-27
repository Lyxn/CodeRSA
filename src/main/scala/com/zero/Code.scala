package com.zero

import java.io.ByteArrayOutputStream
import java.security.{KeyFactory, KeyPair, KeyPairGenerator}
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import javax.crypto.Cipher
import org.apache.commons.codec.binary.Base64

case class RsaKey(publicKey: String, privateKey: String)

object Code {
  val RSA = "RSA"

  def generateKey(keySize: Int): RsaKey = {
    val kpg = KeyPairGenerator.getInstance(RSA)
    kpg.initialize(keySize)
    val keyPair: KeyPair = kpg.generateKeyPair
    val publicKey = Base64.encodeBase64String(keyPair.getPublic.getEncoded)
    val privateKey = Base64.encodeBase64String(keyPair.getPrivate.getEncoded)
    RsaKey(publicKey, privateKey)
  }

  def getCipherPublic(publicKey: String): Cipher = {
    val decodeByte = Base64.decodeBase64(publicKey)
    val key = KeyFactory.getInstance(RSA)
      .generatePublic(new X509EncodedKeySpec(decodeByte))
    val cipher = Cipher.getInstance(RSA)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher
  }

  def getCipherPrivate(privateKey: String): Cipher = {
    val decodeByte = Base64.decodeBase64(privateKey)
    val key = KeyFactory.getInstance(RSA)
      .generatePrivate(new PKCS8EncodedKeySpec(decodeByte))
    val cipher = Cipher.getInstance(RSA)
    cipher.init(Cipher.DECRYPT_MODE, key)
    cipher
  }

  def encryptByPublicKey(data: Array[Byte], publicKey: String): Array[Byte] = {
    val cipher = getCipherPublic(publicKey)
    val size = 117
    decode(cipher, size)(data)
  }

  def decryptByPrivateKey(data: Array[Byte], privateKey: String): Array[Byte] = {
    val cipher = getCipherPrivate(privateKey)
    val size = 128
    decode(cipher, size)(data)
  }

  def decode(cipher: Cipher, size: Int)(data: Array[Byte]): Array[Byte] = {
    val inputLen = data.length
    val out = new ByteArrayOutputStream
    var offset = 0
    var cache: Array[Byte] = null
    var i = 0
    do {
      if (inputLen - offset > size) {
        cache = cipher.doFinal(data, offset, size)
      } else {
        cache = cipher.doFinal(data, offset, inputLen - offset)
      }
      out.write(cache, 0, cache.length)
      i += 1
      offset = i * size
    } while (inputLen - offset > 0)
    out.close()
    out.toByteArray
  }

  def genRsaKey(): Unit = {
    val keySize = 1024
    val rsaKey = generateKey(keySize)
    printf("PublicKey\n%s\n", rsaKey.publicKey)
    printf("PrivateKey\n%s\n", rsaKey.privateKey)
  }

  def main(args: Array[String]): Unit = {
    genRsaKey()
  }
}
