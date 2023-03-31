/*-
 * #%L
 * Nessus DIDComm :: ITests
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.test.cli

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.cli.NessusCli

class SmartSplitTest: AbstractCLITest() {

    @Test
    fun singleDashData() {
        val nessusCli = NessusCli()

        val args = """vc propose -t Passport -i Government.Did -s Malathi.Did -d {"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}"""
        nessusCli.smartSplit(args) shouldBe listOf(
            "vc", "propose",
            "-t", "Passport",
            "-i", "Government.Did",
            "-s", "Malathi.Did",
            "-d", """{"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}""")
    }

    @Test
    fun doubleDashData() {
        val nessusCli = NessusCli()

        val args = """vc propose -t Passport -i Government.Did -s Malathi.Did --data {"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}"""
        nessusCli.smartSplit(args) shouldBe listOf(
            "vc", "propose",
            "-t", "Passport",
            "-i", "Government.Did",
            "-s", "Malathi.Did",
            "--data", """{"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}""")
    }

    @Test
    fun doubleDashDataWithEquals() {
        val nessusCli = NessusCli()

        val args = """vc propose -t Passport -i Government.Did -s Malathi.Did --data={"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}"""
        nessusCli.smartSplit(args) shouldBe listOf(
            "vc", "propose",
            "-t", "Passport",
            "-i", "Government.Did",
            "-s", "Malathi.Did",
            "--data", """{"givenName": "Malathi", "familyName": "Hamal", "citizenship": "US"}""")
    }

    @Test
    fun doubleDashDataWithEqualsInValue() {
        val nessusCli = NessusCli()

        val args = """did create --wallet Hospital --method=peer?numalgo=2"""
        nessusCli.smartSplit(args) shouldBe listOf(
            "did", "create",
            "--wallet", "Hospital",
            "--method", "peer?numalgo=2")
    }

    @Test
    fun singleQuote() {
        val nessusCli = NessusCli()

        val args = """protocol basic-message send 'Your hovercraft is full of eels' --encrypt"""
        nessusCli.smartSplit(args) shouldBe listOf(
            "protocol", "basic-message", "send",
            "Your hovercraft is full of eels",
            "--encrypt")
    }

    @Test
    fun doubleQuote() {
        val nessusCli = NessusCli()

        val args = """protocol basic-message send "Your hovercraft is full of eels" --encrypt"""
        nessusCli.smartSplit(args) shouldBe listOf(
            "protocol", "basic-message", "send",
            "Your hovercraft is full of eels",
            "--encrypt")
    }
}
