package com.roottimer.app

import android.os.Build
import android.os.Environment
import android.os.Process
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Persistent log sink.
 *
 * Writes to /storage/emulated/0/log so logs survive app crashes/panics and
 * device reboots (flushed+synced to disk). Falls back to app-private storage
 * if the primary location is unavailable.
 */
object LogSaver {
    private const val TAG = "LogSaver"
    private const val PRIMARY_DIR = "/storage/emulated/0/log"
    private const val MAX_BYTES = 5L * 1024 * 1024 // 5 MB per file (simple rotation)

    private val started = AtomicBoolean(false)
    private val queue = LinkedBlockingQueue<String>(8192)
    @Volatile private var writerThread: Thread? = null
    @Volatile private var logFile: File? = null
    @Volatile private var fallbackFile: File? = null

    fun init(context: android.content.Context) {
        if (!started.compareAndSet(false, true)) return
        fallbackFile = File(context.filesDir, "logs/samtimer.log")
        installCrashHandler()
        val t = Thread({ writerLoop() }, "samtimer-log-writer")
        t.isDaemon = true
        t.priority = Thread.MIN_PRIORITY
        writerThread = t
        t.start()
        i("LogSaver started pid=${Process.myPid()} uid=${Process.myUid()} sdk=${Build.VERSION.SDK_INT}")
    }

    fun i(msg: String) = append("I", msg)
    fun w(msg: String) = append("W", msg)
    fun e(msg: String, tr: Throwable? = null) {
        val full = if (tr != null) "$msg\n${Log.getStackTraceString(tr)}" else msg
        append("E", full)
    }

    fun append(tag: String, msg: String) {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date())
        val line = "$ts ${Process.myPid()}/$tag: $msg"
        // Also mirror to logcat for debugging
        try { Log.println(if (tag == "E") Log.ERROR else Log.INFO, "SamTimer", line) } catch (_: Throwable) {}
        if (!queue.offer(line)) {
            // drop oldest-ish by clearing and noting; keep recent
            queue.poll()
            queue.offer("$ts ${Process.myPid()}/W: log queue overflow, dropped earlier lines")
            queue.offer(line)
        }
    }

    /** Best-effort synchronous flush for crash handlers. */
    fun flushSync(timeoutMs: Long = 1500) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (queue.isEmpty()) break
            try { Thread.sleep(50) } catch (_: InterruptedException) { break }
        }
        // Writer thread fsyncs on each batch; give it a moment.
        try { Thread.sleep(100) } catch (_: InterruptedException) {}
    }

    private fun installCrashHandler() {
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                append("E", "FATAL uncaught exception in thread ${t.name}\n${Log.getStackTraceString(e)}")
                flushSync(2000)
            } catch (_: Throwable) {
            } finally {
                prev?.uncaughtException(t, e) ?: run {
                    e.printStackTrace()
                    Process.killProcess(Process.myPid())
                }
            }
        }
    }

    private fun writerLoop() {
        while (true) {
            try {
                val first = queue.poll(1, TimeUnit.SECONDS) ?: continue
                val batch = ArrayList<String>(64)
                batch.add(first)
                queue.drainTo(batch, 127)
                writeBatch(batch)
            } catch (_: InterruptedException) {
                break
            } catch (t: Throwable) {
                try { Log.e(TAG, "writer error", t) } catch (_: Throwable) {}
            }
        }
        // drain on exit
        try {
            val rest = ArrayList<String>()
            queue.drainTo(rest)
            if (rest.isNotEmpty()) writeBatch(rest)
        } catch (_: Throwable) {}
    }

    @Synchronized
    private fun writeBatch(lines: List<String>) {
        val targets = listOfNotNull(primaryFile(), fallbackFile)
        for (f in targets) {
            try {
                f.parentFile?.let { if (!it.exists()) it.mkdirs() }
                rotateIfNeeded(f)
                FileOutputStream(f, true).use { fos ->
                    OutputStreamWriter(fos, Charsets.UTF_8).use { w ->
                        for (line in lines) {
                            w.write(line)
                            w.write("\n")
                        }
                        w.flush()
                    }
                    try { fos.fd.sync() } catch (_: Throwable) {}
                }
                return // wrote to preferred/available target
            } catch (_: Throwable) {
                // try next target
            }
        }
    }

    private fun primaryFile(): File? {
        val cur = logFile
        if (cur != null) return cur
        return try {
            val dir = File(PRIMARY_DIR)
            val f = File(dir, "SamTimer.log")
            logFile = f
            f
        } catch (_: Throwable) {
            null
        }
    }

    private fun rotateIfNeeded(f: File) {
        try {
            if (f.exists() && f.length() > MAX_BYTES) {
                val bak = File(f.parentFile, f.name + ".1")
                if (bak.exists()) bak.delete()
                f.renameTo(bak)
            }
        } catch (_: Throwable) {}
    }

    fun logPathHint(): String = PRIMARY_DIR
}
