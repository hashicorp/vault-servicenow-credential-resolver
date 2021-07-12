import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

import java.io.ByteArrayOutputStream

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
tasks.register("copyMidJars") {
	group = "build"
	description = "Copy MID Jars from docker image"
	val srcDir = "/opt/agent/lib"
	val destDir = "build/mid"
	val jars = listOf("mid.jar", "commons-glide.jar")
	outputs.files(jars.map { "${destDir}/${it}" })

	// Code inside doLast will only run if Gradle decides the task needs running,
	// e.g. if the Jars are not already in place.
	doLast {
		println("Copying MID Jars")
		val output = ByteArrayOutputStream()
		exec {
			commandLine("docker", "create", "moers/mid-server:${System.getenv("MID_SERVER_VERSION") ?: "quebec"}")
			standardOutput = output
		}
		val id = output.toString().trim()
		for (jar in jars) {
			exec {
				commandLine("docker", "cp", "${id}:${srcDir}/${jar}", destDir)
			}
		}
		exec {
			commandLine("docker", "rm", "-v", id)
			// Suppress output from docker rm
			standardOutput = output
		}
	}
}

dependencies {
	implementation("com.google.code.gson:gson:2.8.7")
	implementation("org.apache.httpcomponents:httpclient:4.5.13")

	// lib/ folder requires mid.jar and commons-glide.jar to build
	implementation(fileTree("build/mid") {
		include("*.jar")
		builtBy("copyMidJars")
	} )

	testImplementation("junit:junit:4.13.2")
	testImplementation("com.github.tomakehurst:wiremock-jre8:2.28.1")
	testRuntimeOnly("org.slf4j:slf4j-nop:1.7.31")
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
	integrationTestImplementation("org.testcontainers:testcontainers:1.15.3")
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
