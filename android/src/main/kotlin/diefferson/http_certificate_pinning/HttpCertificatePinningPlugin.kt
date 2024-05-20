package diefferson.http_certificate_pinning

import android.os.Handler
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.IOException
import java.net.MalformedURLException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

/** HttpCertificatePinningPlugin */
class HttpCertificatePinningPlugin : FlutterPlugin, MethodCallHandler {

  private var threadExecutorService: ExecutorService? = null
  private var handler: Handler? = null

  init {
    threadExecutorService = Executors.newSingleThreadExecutor()
    handler = Handler(Looper.getMainLooper())
  }

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    val channel = MethodChannel(binding.binaryMessenger, "http_certificate_pinning")
    channel.setMethodCallHandler(HttpCertificatePinningPlugin())
  }


  override fun onMethodCall(call: MethodCall, result: Result) {
    try {
      when (call.method) {
        "check" -> {
          if(isThreadTerminate()) {
            result.success("CONNECTION_SECURE")
          } else {
            threadExecutorService?.execute {
              handleCheckEvent(call, result)
            }
          }
        }
        else -> result.notImplemented()
      }
    } catch (e: Exception) {
      handler?.post {
        result.error(e.toString(), "", "")
      }
    }
  }

  private fun isThreadTerminate(): Boolean {
     var ret = threadExecutorService?.isShutdown
     if(ret != false) {
       return true
     }
    ret = threadExecutorService?.isTerminated
    return ret != false
  }

  private fun handleCheckEvent(call: MethodCall, result: Result) {
    try {
      val arguments: HashMap<String, Any> = call.arguments as HashMap<String, Any>
      val serverURL: String = arguments["url"] as String
      val allowedFingerprints: List<String> = arguments["fingerprints"] as List<String>
      val httpHeaderArgs: Map<String, String> = arguments["headers"] as Map<String, String>
      val timeout: Int = arguments["timeout"] as Int
      val type: String = arguments["type"] as String
      if (this.checkConnexion(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type)) {
        handler?.post {
          result.success("CONNECTION_SECURE")
        }
      } else {
        handler?.post {
          result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Fingerprint doesn't match")
        }
      }
    } catch (e: UnknownHostException) {
      handler?.post {
        result.error("NO_INTERNET", "No Internet Connection", " ")
      }
    } catch (e: SocketTimeoutException) {
      handler?.post {
        result.error("TIMEOUT", "Connection Timeout", " ")
      }
    } catch (e: IOException) {
      handler?.post {
        result.error("NETWORK_ERROR", "Network Error", " ")
      }
    } catch(e: MalformedURLException) {
      handler?.post {
        result.error("URL_ERROR", "MalformedURLException", " ")
      }
    }
    catch (e: Exception) {
      handler?.post {
        result.error("UNKNOWN_ERROR", "An Unknown Error Occurred", " ")
      }
    }
  }


  private fun checkConnexion(serverURL: String, allowedFingerprints: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, type: String): Boolean {
    val sha: String = this.getFingerprint(serverURL, timeout, httpHeaderArgs, type)
    return allowedFingerprints.map { fp -> fp.uppercase().replace("\\s".toRegex(), "") }.contains(sha)
  }

  private fun getFingerprint(httpsURL: String, connectTimeout: Int, httpHeaderArgs: Map<String, String>, type: String): String {
    try {
      val url = URL(httpsURL)
      val httpClient: HttpsURLConnection = url.openConnection() as HttpsURLConnection
      if (connectTimeout > 0) {
        httpClient.connectTimeout = connectTimeout * 1000
      }
      httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }
      httpClient.connect()
      val cert: Certificate = httpClient.serverCertificates[0] as Certificate
      return this.hashString(type, cert.encoded)
    } catch (e: Exception) {
       throw e
    }
  }

  private fun hashString(type: String, input: ByteArray) =
    MessageDigest
      .getInstance(type)
      .digest(input).joinToString(separator = "") { String.format("%02X", it) }


  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    try {
      threadExecutorService?.shutdown()
    }catch (_: Exception){}
  }
}
