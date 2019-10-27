package com.zero

import java.io.{File, FileInputStream, FileOutputStream}

object Misc {

  def readBuffer(filename: String): Array[Byte] = {
    val file = new File(filename)
    val buf = new Array[Byte](file.length().toInt)
    val strIn = new FileInputStream(filename)
    val size = strIn.read(buf)
    printf("Filename=%s FileSize=%d ReadSize=%d\n", filename, file.length(), size)
    strIn.close()
    buf
  }

  def writeBuffer(filename: String, data: Array[Byte]): Unit = {
    val strOut = new FileOutputStream(filename)
    strOut.write(data)
    printf("Filename=%s WriteSize=%d\n", filename, data.length)
    strOut.close()
  }

  def encryptFile(filename: String, publicKey: String): Array[Byte] = {
    val buf = readBuffer(filename)
    Code.encryptByPublicKey(buf, publicKey)
  }

  def decryptFile(filename: String, privateKey: String): Array[Byte] = {
    val buf = readBuffer(filename)
    Code.decryptByPrivateKey(buf, privateKey)
  }
}

object App {

  def main(args: Array[String]): Unit = {
    val flag = args(0)
    if (flag == "k") {
      Code.genRsaKey()
      return
    }

    val fileKey = args(1)
    val fileIn = args(2)
    val fileOut = args(3)
    val key = new String(Misc.readBuffer(fileKey))
    printf("RsaKey\n%s\n", key)

    var buf: Array[Byte] = null
    if (flag == "e") {
      buf = Misc.encryptFile(fileIn, key)
    } else if (flag == "d") {
      buf = Misc.decryptFile(fileIn, key)
    }
    Misc.writeBuffer(fileOut, buf)
  }
}
