/*
 * Copyright (c) HashiCorp, Inc.
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
	implementation("com.google.code.gson:gson:2.8.8")
	implementation("org.apache.httpcomponents:httpclient:4.5.13")

	// lib/ folder requires mid.jar and commons-glide.jar to build
	implementation(fileTree("build/mid") {
		include("*.jar")
		builtBy("copyMidJars")
	} )

	testImplementation("junit:junit:4.13.2")
	testImplementation("com.github.tomakehurst:wiremock-jre8:2.31.0")
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
	integrationTestImplementation("commons-io:commons-io:2.11.0")
	integrationTestImplementation(platform("com.squareup.okhttp3:okhttp-bom:4.9.1"))
	integrationTestImplementation("com.squareup.okhttp3:okhttp-tls")
	integrationTestRuntimeOnly("org.slf4j:slf4j-nop:1.7.31")
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

	from(sourceSets.main.get().output)

	dependsOn(configurations.runtimeClasspath)
	from({
		configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map {
			exclude("META-INF/*")
			if (it.isDirectory) it else zipTree(it)
		}
	})
}