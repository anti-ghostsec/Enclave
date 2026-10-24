package app.enclave.ui.screens

import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.graphics.drawable.AnimatedImageDrawable
import android.graphics.drawable.Drawable
import android.media.MediaPlayer
import android.view.Surface
import android.view.TextureView
import android.widget.ImageView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.VerticalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.VolumeOff
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Slideshow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.ui.Opener
import app.enclave.vault.EncryptedMediaSource
import app.enclave.vault.Entry
import app.enclave.vault.Media
import app.enclave.vault.VaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer

/**
 * Full-screen viewer for photos, GIFs, videos, audio and text. Swipe to move between files
 * (sideways or up/down, from Settings), pinch or double-tap to zoom, and run a slideshow.
 * Everything is decrypted in memory only.
 */
@Composable
fun ViewerScreen(store: VaultStore, items: List<Entry>, start: Int, onClose: () -> Unit) {
    BackHandler(onBack = onClose)
    val ctx = LocalContext.current
    val settings by store.settings.collectAsStateWithLifecycle()
    val pager = rememberPagerState(initialPage = start.coerceIn(0, (items.size - 1).coerceAtLeast(0))) { items.size }
    var slideshow by remember { mutableStateOf(false) }
    var zoomed by remember { mutableStateOf(false) }
    var chrome by remember { mutableStateOf(true) }
    // Lets the slideshow wait for a video or song to finish before moving on.
    var mediaPlaying by remember { mutableStateOf(false) }

    val view = LocalView.current
    DisposableEffect(slideshow) {
        view.keepScreenOn = slideshow
        onDispose { view.keepScreenOn = false }
    }
    LaunchedEffect(slideshow, pager.currentPage) {
        if (!slideshow) return@LaunchedEffect
        delay(settings.slideshowSeconds * 1000L)
        while (mediaPlaying) delay(300)
        if (pager.currentPage < items.size - 1) pager.animateScrollToPage(pager.currentPage + 1) else slideshow = false
    }
    LaunchedEffect(pager.currentPage) { zoomed = false; mediaPlaying = false }

    val current = items.getOrNull(pager.currentPage) ?: return onClose()

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        val page: @Composable (Int) -> Unit = { i ->
            val e = items[i]
            val active = i == pager.currentPage
            when {
                Media.isVideo(e) || Media.isAudio(e) -> PlayerPage(
                    store, e, active, autoPlay = slideshow,
                    onPlayingChange = { if (active) mediaPlaying = it },
                )
                Media.isImage(e) -> ImagePage(store, e, active, onZoomChange = { if (active) zoomed = it }, onTap = { chrome = !chrome })
                else -> TextPage(store, e)
            }
        }
        if (settings.swipeVertical) {
            VerticalPager(pager, Modifier.fillMaxSize(), userScrollEnabled = !zoomed, key = { items[it].id }) { page(it) }
        } else {
            HorizontalPager(pager, Modifier.fillMaxSize(), userScrollEnabled = !zoomed, key = { items[it].id }) { page(it) }
        }

        if (chrome) Row(
            Modifier.fillMaxWidth().background(Color.Black.copy(alpha = 0.45f)).systemBarsPadding().padding(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClose) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Color.White) }
            Column(Modifier.weight(1f)) {
                Text(current.name, color = Color.White, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text("${pager.currentPage + 1} of ${items.size}", color = Color.White.copy(alpha = 0.7f), style = androidx.compose.material3.MaterialTheme.typography.labelSmall)
            }
            if (items.size > 1) IconButton(onClick = { slideshow = !slideshow }) {
                Icon(if (slideshow) Icons.Default.Stop else Icons.Default.Slideshow, if (slideshow) "Stop slideshow" else "Slideshow", tint = Color.White)
            }
            IconButton(onClick = { Opener.share(ctx, store, listOf(current)) }) { Icon(Icons.Default.Share, "Share", tint = Color.White) }
            IconButton(onClick = { Opener.openExternally(ctx, store, current, alwaysAsk = true) }) {
                Icon(Icons.AutoMirrored.Filled.OpenInNew, "Open with another app", tint = Color.White)
            }
        }
    }
}

/** A still image, or an animated one (GIF / animated WebP) that actually plays. */
@Composable
private fun ImagePage(store: VaultStore, e: Entry, active: Boolean, onZoomChange: (Boolean) -> Unit, onTap: () -> Unit) {
    val loaded by produceState<Any?>(null, e.id) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                if (Media.mayAnimate(e) && e.size < 64L * 1024 * 1024) {
                    val bytes = Media.readAll(store, e)
                    val d = ImageDecoder.decodeDrawable(ImageDecoder.createSource(ByteBuffer.wrap(bytes)))
                    if (d is AnimatedImageDrawable) return@runCatching d
                }
                Media.decodeImage(store, e, 2560)
            }.getOrNull() ?: "failed"
        }
    }
    var scale by remember { mutableFloatStateOf(1f) }
    var offset by remember { mutableStateOf(Offset.Zero) }
    val transform = rememberTransformableState { zoom, pan, _ ->
        scale = (scale * zoom).coerceIn(1f, 6f)
        offset = if (scale == 1f) Offset.Zero else offset + pan
    }
    LaunchedEffect(active) { if (!active) { scale = 1f; offset = Offset.Zero } }
    LaunchedEffect(scale) { onZoomChange(scale > 1f) }

    val zoomable = Modifier.fillMaxSize()
        .pointerInput(e.id) {
            detectTapGestures(
                onTap = { onTap() },
                onDoubleTap = { if (scale > 1f) { scale = 1f; offset = Offset.Zero } else scale = 2.5f },
            )
        }
        .transformable(transform, canPan = { scale > 1f })
        .graphicsLayer(scaleX = scale, scaleY = scale, translationX = offset.x, translationY = offset.y)

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        when (val l = loaded) {
            null -> CircularProgressIndicator()
            is Bitmap -> Image(l.asImageBitmap(), e.name, zoomable, contentScale = ContentScale.Fit)
            is Drawable -> {
                AndroidView(
                    factory = { ImageView(it).apply { scaleType = ImageView.ScaleType.FIT_CENTER } },
                    update = { iv -> iv.setImageDrawable(l); (l as? AnimatedImageDrawable)?.start() },
                    modifier = zoomable,
                )
                DisposableEffect(l) { onDispose { (l as? AnimatedImageDrawable)?.stop() } }
            }
            else -> Text("This image can't be shown here.", color = Color.White)
        }
    }
}

/** Plays a video or song straight from the encrypted file. */
@Composable
private fun PlayerPage(store: VaultStore, e: Entry, active: Boolean, autoPlay: Boolean, onPlayingChange: (Boolean) -> Unit) {
    val isVideo = Media.isVideo(e)
    var player by remember { mutableStateOf<MediaPlayer?>(null) }
    var surface by remember { mutableStateOf<Surface?>(null) }
    var prepared by remember { mutableStateOf(false) }
    var playing by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    var duration by remember { mutableIntStateOf(0) }
    var position by remember { mutableIntStateOf(0) }
    var aspect by remember { mutableFloatStateOf(16f / 9f) }
    // Every video and song starts silent; raise it with the volume slider.
    var volume by remember { mutableFloatStateOf(0f) }
    var lastVolume by remember { mutableFloatStateOf(0.5f) }

    fun setPlaying(p: Boolean) {
        playing = p; onPlayingChange(p)
    }

    DisposableEffect(e.id) {
        val mp = MediaPlayer()
        runCatching {
            mp.setDataSource(EncryptedMediaSource(store.reader(e)))
            mp.setVolume(0f, 0f)
            mp.setOnPreparedListener {
                prepared = true
                duration = it.duration
                if (it.videoWidth > 0 && it.videoHeight > 0) aspect = it.videoWidth.toFloat() / it.videoHeight
            }
            mp.setOnVideoSizeChangedListener { _, w, h -> if (w > 0 && h > 0) aspect = w.toFloat() / h }
            mp.setOnCompletionListener { setPlaying(false) }
            mp.setOnErrorListener { _, _, _ -> failed = true; setPlaying(false); true }
            mp.prepareAsync()
        }.onFailure { failed = true }
        player = mp
        onDispose {
            onPlayingChange(false)
            mp.release()
        }
    }
    LaunchedEffect(player, surface) { surface?.let { player?.setSurface(it) } }
    LaunchedEffect(player, volume) { runCatching { player?.setVolume(volume, volume) } }
    LaunchedEffect(active, prepared, autoPlay) {
        val mp = player ?: return@LaunchedEffect
        if (!prepared) return@LaunchedEffect
        if (!active && mp.isPlaying) { mp.pause(); setPlaying(false) }
        if (active && autoPlay && !mp.isPlaying) { mp.start(); setPlaying(true) }
    }
    LaunchedEffect(playing) {
        while (playing) {
            position = runCatching { player?.currentPosition ?: 0 }.getOrDefault(0)
            delay(250)
        }
    }

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        if (isVideo) {
            AndroidView(
                factory = { c ->
                    TextureView(c).apply {
                        surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                            override fun onSurfaceTextureAvailable(st: android.graphics.SurfaceTexture, w: Int, h: Int) { surface = Surface(st) }
                            override fun onSurfaceTextureSizeChanged(st: android.graphics.SurfaceTexture, w: Int, h: Int) {}
                            override fun onSurfaceTextureDestroyed(st: android.graphics.SurfaceTexture): Boolean { surface = null; return true }
                            override fun onSurfaceTextureUpdated(st: android.graphics.SurfaceTexture) {}
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth().aspectRatio(aspect),
            )
        } else {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.MusicNote, null, Modifier.size(96.dp), tint = Color.White.copy(alpha = 0.6f))
                Text(e.name, color = Color.White, modifier = Modifier.padding(16.dp))
            }
        }
        when {
            failed -> Text("This file can't be played here. Use “Open with another app”.", color = Color.White, modifier = Modifier.padding(24.dp))
            !prepared -> CircularProgressIndicator()
        }
        if (prepared && !failed) Column(
            Modifier.align(Alignment.BottomCenter).fillMaxWidth().background(Color.Black.copy(alpha = 0.45f)).systemBarsPadding().padding(horizontal = 12.dp),
        ) {
            Slider(
                value = if (duration > 0) position.toFloat() / duration else 0f,
                onValueChange = { f -> position = (f * duration).toInt(); player?.seekTo(position) },
            )
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                IconButton(onClick = {
                    val mp = player ?: return@IconButton
                    if (mp.isPlaying) { mp.pause(); setPlaying(false) } else { mp.start(); setPlaying(true) }
                }) { Icon(if (playing) Icons.Default.Pause else Icons.Default.PlayArrow, if (playing) "Pause" else "Play", tint = Color.White) }
                Text("${time(position)} / ${time(duration)}", color = Color.White, modifier = Modifier.weight(1f))
                IconButton(onClick = {
                    if (volume > 0f) { lastVolume = volume; volume = 0f } else volume = lastVolume.coerceAtLeast(0.1f)
                }) {
                    Icon(
                        if (volume == 0f) Icons.AutoMirrored.Filled.VolumeOff else Icons.AutoMirrored.Filled.VolumeUp,
                        if (volume == 0f) "Unmute" else "Mute", tint = Color.White,
                    )
                }
                Slider(value = volume, onValueChange = { volume = it }, modifier = Modifier.width(120.dp))
            }
        }
    }
}

private fun time(ms: Int): String {
    val s = ms / 1000
    return if (s >= 3600) "%d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60) else "%d:%02d".format(s / 60, s % 60)
}

@Composable
private fun TextPage(store: VaultStore, e: Entry) {
    val text by produceState<String?>(null, e.id) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                store.reader(e).use { r ->
                    val max = minOf(r.size, 2L * 1024 * 1024).toInt()
                    val buf = ByteArray(max)
                    String(buf, 0, r.read(0, buf, 0, max).coerceAtLeast(0))
                }
            }.getOrDefault("This file can't be shown here.")
        }
    }
    Box(Modifier.fillMaxSize().systemBarsPadding()) {
        text?.let {
            Text(
                it, Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(top = 56.dp, start = 16.dp, end = 16.dp, bottom = 16.dp),
                color = Color.White, fontFamily = FontFamily.Monospace,
            )
        } ?: CircularProgressIndicator(Modifier.align(Alignment.Center))
    }
}
