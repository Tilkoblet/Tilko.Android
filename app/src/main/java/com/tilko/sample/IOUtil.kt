package com.tilko.sample

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.lang.Exception

class IOUtil(private val context: Context) {
    fun saveFile(filePath: String, fileName: String?, certData: ByteArray?) {
        val directory = File(context.filesDir.toString() + filePath)
        if (!directory.exists()) {
            directory.mkdirs()
        }
        val file = File(context.filesDir.toString() + filePath, fileName)
        val outputStream: FileOutputStream
        try {
            file.createNewFile()
            outputStream = FileOutputStream(file)
            outputStream.write(certData)
            outputStream.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}