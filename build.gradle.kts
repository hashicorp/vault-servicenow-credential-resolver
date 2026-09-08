/*
 * Copyright IBM Corp. 2021, 2026
 * SPDX-License-Identifier: MPL-2.0
 */

import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputFiles
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.process.ExecOperations

import java.io.ByteArrayOutputStream
import javax.inject.Inject

plugins {
	// https://docs.gradle.org/current/userguide/java_plugin.html#java_plugin
	java
}

java {
	sourceCompatibility = JavaVersion.VERSION_1_8
	targetCompatibility = JavaVersion.VERSION_1_8
}

repositories {
	// Use Maven Central for resolving dependencies.
	mavenCentral()
}

sourceSets {
	main {
		java {
			srcDir("src/main/java")
		}
	}

	test {
		java {
			srcDir("src/test/java")
		}
	}
}

// Copy mid jars for build
abstract class CopyMidJars @Inject constructor(private val execOps: ExecOperations) : DefaultTask() {
	@get:Input
	val srcDir = "/opt/agent/lib"

	@get:Input
	val destDir = "build/mid"

	@get:Input
	val jars = listOf(
        "commons-core-automation.jar",
        "commons-glide.jar",
        "guava.jar",
        "mid.jar",
        "snc-automation-api.jar",
    )

	@get:OutputFiles
	val outputFiles = jars.map { File("${destDir}/${it}") }

	@TaskAction
	fun copyJars() {
		println("Copying MID Jars")
		val output = ByteArrayOutputStream()
		execOps.exec {
			commandLine("docker", "create", "moers/mid-server:${System.getenv("MID_SERVER_VERSION") ?: "washingtondc.08-31-2024_1809"}")
			standardOutput = output
		}
		val id = output.toString().trim()
		for (jar in jars) {
			execOps.exec {
				commandLine("docker", "cp", "${id}:${srcDir}/${jar}", destDir)
			}
		}
		execOps.exec {
			commandLine("docker", "rm", "-v", id)
			// Suppress output from docker rm
			standardOutput = output
		}
	}
}

tasks.register<CopyMidJars>("copyMidJars") {
	group = "build"
	description = "Copy MID Jars from docker image"
}

dependencies {
	implementation("com.google.code.gson:gson:2.14.0")
	implementation("org.apache.httpcomponents:httpclient:4.5.14")

	// lib/ folder requires mid.jar and commons-glide.jar to build
	implementation(fileTree("build/mid") {
		include("*.jar")
		builtBy("copyMidJars")
	} )

	testImplementation("junit:junit:4.13.2")
	testImplementation("com.github.tomakehurst:wiremock-jre8:2.35.2")
	testRuntimeOnly("org.slf4j:slf4j-nop:1.7.32")
}

// Integration test definition based on:
// https://docs.gradle.org/current/userguide/java_testing.html#sec:configuring_java_integration_tests
sourceSets {
	create("integrationTest") {
		java {
			// Requires main sourceSet to build and run
			compileClasspath += sourceSets.main.get().output
			runtimeClasspath += sourceSets.main.get().output
			srcDir("src/integrationTest/java")
		}
	}
}

val integrationTestImplementation by configurations.getting {
	extendsFrom(configurations.implementation.get())
}

val integrationTestRuntimeOnly by configurations.getting {
	extendsFrom(configurations.runtimeOnly.get())
}

dependencies {
	integrationTestImplementation("junit:junit:4.13.2")
	integrationTestImplementation("org.testcontainers:testcontainers:2.0.3")
	integrationTestImplementation("commons-io:commons-io:2.20.0")
	integrationTestImplementation(platform("com.squareup.okhttp3:okhttp-bom:4.12.0"))
	integrationTestImplementation("com.squareup.okhttp3:okhttp-tls")
	integrationTestRuntimeOnly("org.slf4j:slf4j-nop:1.7.31")
}

// Patched versions for libraries that reach the build only through WireMock and
// Testcontainers. Constraining them here keeps the test classpath clean without
// touching the shipped artifact, which resolves these from no other source.
val testOnlySecurityUpgrades = listOf(
	"com.fasterxml.jackson.core:jackson-annotations:2.22",
	"com.fasterxml.jackson.core:jackson-core:2.22.2",
	"com.fasterxml.jackson.core:jackson-databind:2.22.2",
	"com.github.jknack:handlebars:4.5.4",
	"com.github.jknack:handlebars-helpers:4.5.4",
	"com.google.guava:guava:33.7.1-jre",
	"com.jayway.jsonpath:json-path:2.9.0",
	"commons-fileupload:commons-fileupload:1.6.0",
	"commons-io:commons-io:2.20.0",
	"net.minidev:json-smart:2.6.0",
	"org.apache.commons:commons-lang3:3.20.0",
	"org.apache.httpcomponents.client5:httpclient5:5.6.4",
	"org.apache.httpcomponents.core5:httpcore5:5.4.3",
	"org.apache.httpcomponents.core5:httpcore5-h2:5.4.3",
	"org.eclipse.jetty.http2:http2-common:9.4.58.v20250814",
	"org.eclipse.jetty.http2:http2-hpack:9.4.58.v20250814",
	"org.eclipse.jetty.http2:http2-server:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-client:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-http:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-io:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-proxy:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-security:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-server:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-servlet:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-servlets:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-util:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-webapp:9.4.58.v20250814",
	"org.eclipse.jetty:jetty-xml:9.4.58.v20250814",
	"org.xmlunit:xmlunit-core:2.13.0",
)

dependencies {
	constraints {
		testOnlySecurityUpgrades.forEach { coordinate ->
			add("testImplementation", coordinate)
			add("integrationTestImplementation", coordinate)
		}
	}
}

// Create the gradle task so we can run `./gradlew integrationTest`
val integrationTest = task<Test>("integrationTest") {
	description = "Runs integration tests."
	group = "verification"

	testClassesDirs = sourceSets["integrationTest"].output.classesDirs
	classpath = sourceSets["integrationTest"].runtimeClasspath
	shouldRunAfter("test")
	
}

tasks.check { dependsOn(integrationTest) }

// Common test settings
tasks.withType<Test> {
	testLogging {
		showStackTraces = true
		exceptionFormat = TestExceptionFormat.FULL
		events(TestLogEvent.FAILED, TestLogEvent.SKIPPED, TestLogEvent.PASSED)
		// Uncomment to get log output from `gradle test`.
		//showStandardStreams = true
	}
}

// Create an uber JAR:
// https://docs.gradle.org/current/userguide/working_with_files.html#sec:creating_uber_jar_example
tasks.register<Jar>("uberJar") {
	manifest {
		attributes["Main-Class"] = "com.snc.discovery.CredentialResolver"
	}

	archiveClassifier.set("uber")

	// Bundled dependencies ship multi-release metadata (META-INF/versions/**) that
	// collides when flattened; the first occurrence wins.
	duplicatesStrategy = DuplicatesStrategy.EXCLUDE

	from(sourceSets.main.get().output)

	dependsOn(configurations.runtimeClasspath)
	from({
		configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map {
			exclude("META-INF/*")
			if (it.isDirectory) it else zipTree(it)
		}
	})
}

// Lock resolved dependency versions so OSV-Scanner can read gradle.lockfile.
// Regenerate after changing dependencies: ./gradlew dependencies --write-locks
dependencyLocking {
	lockAllConfigurations()
}
