package com.tilko.sample

import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Base64
import android.util.Log
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import microsoft.aspnet.signalr.client.hubs.HubConnection
import org.json.JSONObject
import org.slf4j.helpers.Util
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.URLEncoder
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

const val ALGORITHM = "AES"
const val PADDING_MODE = "/CBC/PKCS7Padding"
const val RSA_ALGORITHM = "RSA/ECB/PKCS1Padding"

data class CertInfo(
    var filePath: String = "",
    var cn:String= "",
    var validDate:String = ""
)

fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }
fun String.hexStringToByteArray() = ByteArray(this.length / 2) {
    this.substring(
        it * 2,
        it * 2 + 2
    ).toInt(16).toByte()
}

private val HEX_CHARS = "0123456789ABCDEF".toCharArray()
fun ByteArray.toHex() : String{
    val result = StringBuffer()

    forEach {
        val octet = it.toInt()
        val firstIndex = (octet and 0xF0).ushr(4)
        val secondIndex = octet and 0x0F
        result.append(HEX_CHARS[firstIndex])
        result.append(HEX_CHARS[secondIndex])
    }

    return result.toString()
}

@RequiresApi(Build.VERSION_CODES.O)
class MainActivity : AppCompatActivity() {
    private var rsa:RSA? = null
    private val server_url = "https://cert.tilko.net/"
    private var pem:String = ""
    private var hubConnection:HubConnection? = null
    val dateFormat = SimpleDateFormat("yyyy.MM.dd")


    private var ioUtil:IOUtil? = null;


    // 인증서 목록 불러오기
    fun readCertificates() {

        var certs = arrayListOf<CertInfo>()

        var arrCert = arrayListOf<String>()
        val folder = File(getFilesDir().toString() + "/NPKI")
        if (folder.exists()) {
            val children1 = folder.list()
            for (i in children1.indices) {
                val subFolder1 = File(folder, children1[i].toString() + "/USER")
                if (subFolder1.exists()) {
                    val children2 = subFolder1.list()
                    for (j in children2.indices) {
                        val subFolder2 = File(subFolder1, children2[j])
                        arrCert.add(subFolder2.absolutePath)

                        // 파일명 소문자로 변환
                        val subChildren = subFolder2.list()
                        for (childIdx in subChildren.indices) {
                            subChildren[childIdx] = subChildren[childIdx].toLowerCase()
                        }
                        val list: List<String> = subChildren.toList()
                        if (!list.contains("signcert.der") || !list.contains("signpri.key")) {
                            arrCert.removeAt(arrCert.size - 1)
                        }
                    }
                }
            }
        }
        for (i in arrCert.indices) {
            val info = CertInfo()
            info.filePath = arrCert[i]
            val derFile = File(arrCert[i], "signCert.der")
            try {
                val cf: CertificateFactory = CertificateFactory.getInstance("X.509")
                val cert: X509Certificate =
                    cf.generateCertificate(FileInputStream(derFile)) as X509Certificate


                //cn
                val dn: String = cert.getSubjectDN().toString()
                Log.wtf("DN: ", dn)

                val split = dn.split(",".toRegex()).toTypedArray()
                for (x in split) {
                    if (x.contains("CN=")) {
                        var cn = x.trim { it <= ' ' }.replace("CN=", "")
                        println("CN is $cn")
                        cn = cn.replace("\\p{Punct}|\\p{Digit}|[A-Za-z]".toRegex(), "")
                        info.cn = cn
                    }
                }


                //valid date
                val validFrom: String = dateFormat.format(cert.notBefore)
                val validTo: String = dateFormat.format(cert.notAfter)
                println("Valid Date = $validFrom - $validTo")
                info.validDate = "$validFrom - $validTo"

            } catch (ex: java.lang.Exception) {
                ex.printStackTrace()
            }
            certs.add(info)
        }

        parseCerts(certs)
    }

    // 인증서 목록 표시
    fun parseCerts(certs:ArrayList<CertInfo>) {
        certsLayout.removeAllViewsInLayout()

        certs.forEach {

            Log.wtf("CERTIFICATE: ", it.toString())
            val tv = TextView(this)
            tv.text = "${it.cn} / ${it.validDate}"
            certsLayout.addView(tv)

        }

    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)



        readCertificates()

        ioUtil = IOUtil(this);
        /*if (checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                arrayOf(
                    android.Manifest.permission.WRITE_EXTERNAL_STORAGE,
                    android.Manifest.permission.READ_EXTERNAL_STORAGE
                ), 101
            )
        }*/


        rsa = RSA()
        rsa!!.generatorKey()




        button.setOnClickListener {
            pem = Base64.encodeToString(rsa!!.publicKey.encoded, 0)

            Log.wtf("BASE 64 Public Key", pem)
            Log.wtf("Public Key After URL Encoding", URLEncoder.encode(pem, "UTF-8"))


            hubConnection = HubConnection(server_url)
            val mHub = hubConnection!!.createHubProxy("AuthHub")
            hubConnection!!.headers.put("client_type", "Mobile")
            hubConnection!!.headers.put("public_cert", URLEncoder.encode(pem, "UTF-8"))
            hubConnection!!.connected {
                Log.d("CODE RECEIVED", "CONNECTED")

            }
            hubConnection!!.closed {

            }
            hubConnection!!.received {
                Log.d("CODE RECEIVED", "RECEIVED")

                Log.d("JSON", it.toString())

                val obj = JSONObject(it.toString())

                when (obj.getString("M")) {
                    "ShowCode" -> {
                        val arr = obj.getJSONArray("A")
                        Log.wtf("NUMBER:", arr.getString(0))
                        var code = arr.getString(0)

                        runOnUiThread {
                            codeText.text = code.substring(0, 4) + " " + code.substring(4, 8)
                        }
                    }

                    "SaveCertificate" -> {

                        val arr = obj.getJSONArray("A")

                        val encryptedAesKey = arr.getString(0)
                        val encryptedPublicKey = arr.getString(1)
                        val encryptedPrivateKey = arr.getString(2)
                        val subjectDN = arr.getString(3)
                        val sessionId = arr.getString(4)

                        Log.d("암호화된 AES 키: ", "$encryptedAesKey")
                        Log.d("SubjectDN: ", "$subjectDN")
                        Log.d("암호화된 공개키 HEX 정보: ", "$encryptedPublicKey")
                        Log.d("암호화된 개인키 HEX 정보: ", "$encryptedPrivateKey")
                        Log.d("SessionId: ", "$sessionId")

                        val hexAesKeyByteArray = encryptedAesKey.hexStringToByteArray()
                        val decryptedAesKey = decryptWithRSA(hexAesKeyByteArray, rsa!!.privateKey)!!

                        val iv = byteArrayOfInts(
                            123,
                            140,
                            56,
                            128,
                            22,
                            11,
                            170,
                            121,
                            33,
                            113,
                            73,
                            28,
                            208,
                            42,
                            247,
                            134
                        )

                        val decryptedPublicBytes = decryptWithAES(
                            decryptedAesKey,
                            iv,
                            encryptedPublicKey.hexStringToByteArray()
                        )!!
                        val decryptedPrivateBytes = decryptWithAES(
                            decryptedAesKey,
                            iv,
                            encryptedPrivateKey.hexStringToByteArray()
                        )!!


                        val e1 = String(decryptedPublicBytes).hexStringToByteArray()
                        val e2 = String(decryptedPrivateBytes).hexStringToByteArray()

                        var issuedBy = ""
                        val dnList = subjectDN.split(",")
                        dnList.forEach {

                            Log.wtf("dn: ", it)

                            val dn = it.split("=")
                            if (dn[0] == "O") {
                                issuedBy = dn[1]
                                Log.wtf("Issued By:", issuedBy)
                            }
                        }

                        if (issuedBy.equals("")) {
                            return@received
                        }

                        val username = subjectDN

                        val path = "/NPKI/${issuedBy}/USER/"+username;
                        ioUtil!!.saveFile(path, "signCert.der", e1);
                        ioUtil!!.saveFile(path, "signPri.key", e2);

                        runOnUiThread {
                            Toast.makeText(this, "Done", Toast.LENGTH_LONG).show()
                            readCertificates()
                        }
                    }
                }
            }

            hubConnection!!.error {
                Log.e("ERR", it.localizedMessage)
            }

            try {

                var awaitConnection = hubConnection!!.start()
                awaitConnection.get()

            } catch (e: Exception) {
                Log.e("SignalR Error", e.localizedMessage)
            }
        }
    }


    private fun decryptWithAES(
        aesKey: ByteArray, aesIV: ByteArray,
        encryptedData: ByteArray
    ): ByteArray? {
        val skeySpec = SecretKeySpec(aesKey, ALGORITHM)
        val aesCipher = Cipher.getInstance(
            ALGORITHM + PADDING_MODE
        )

        aesCipher.init(
            Cipher.DECRYPT_MODE, skeySpec,
            IvParameterSpec(aesIV)
        )

        return aesCipher.doFinal(encryptedData)
    }

    private fun decryptWithRSA(encryptedAesKey: ByteArray, privKey: PrivateKey): ByteArray? {
        val rsaCipher = Cipher.getInstance(RSA_ALGORITHM)
        rsaCipher.init(Cipher.DECRYPT_MODE, privKey)
        return rsaCipher.doFinal(encryptedAesKey)
    }



    override fun onDestroy() {
        super.onDestroy()
        hubConnection?.stop()

    }



}
