# Hollow release rules (M3-5). R8 minifies the Kotlin shell; the
# gomobile seam must survive untouched: the generated binding classes
# call our Kotlin implementations (SecretBox, Protector) reflectively
# through JNI proxies, and the Go side reaches the facade by name.
-keep class hollowcore.** { *; }
-keep class session.** { *; }
-keep class core.** { *; }
-keep class eu.org.brodydung.hollow.** { *; }
# ZXing decoders are reached through MultiFormatReader's registry.
-keep class com.google.zxing.** { *; }
