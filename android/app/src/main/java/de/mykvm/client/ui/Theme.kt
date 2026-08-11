package de.mykvm.client.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * The desktop app's palette, so the two look like one product.
 *
 * Taken from its stylesheet rather than approximated: #18181b on #f4f4f5 in
 * dark, and the white cards on #f2f5fa in light.
 */
private val Dark = darkColorScheme(
    background = Color(0xFF18181B),
    surface = Color(0xFF1F1F23),
    surfaceVariant = Color(0xFF27272B),
    onBackground = Color(0xFFF4F4F5),
    onSurface = Color(0xFFF4F4F5),
    onSurfaceVariant = Color(0xFFA1A1AA),
    primary = Color(0xFF60A5FA),
    onPrimary = Color(0xFF0F2857),
    outline = Color(0xFF3F3F46),
    error = Color(0xFFF87171),
)

private val Light = lightColorScheme(
    background = Color(0xFFF2F5FA),
    surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFF6F8FC),
    onBackground = Color(0xFF172033),
    onSurface = Color(0xFF172033),
    onSurfaceVariant = Color(0xFF5B6478),
    primary = Color(0xFF2563EB),
    onPrimary = Color(0xFFFFFFFF),
    outline = Color(0xFFD7DEEA),
    error = Color(0xFFDC2626),
)

@Composable
fun MyKvmTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
}
