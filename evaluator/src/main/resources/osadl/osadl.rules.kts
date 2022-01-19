/*
 * Copyright (C) 2022 Bosch.IO GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

// Use this rule like:
//
// $ ort evaluate -i scanner/src/funTest/assets/dummy-expected-output-for-analyzer-result.yml --rules-resource /osadl/osadl.rules.kts

enum class Compatibility {
    INHERENT,
    YES,
    NO,
    UNKNOWN;

    companion object {
        fun fromString(value: String): Compatibility =
            when (value) {
                "", "Same" -> INHERENT
                "Yes" -> YES
                "No" -> NO
                "?", "Unknown", "Check dependency", "Dep." -> UNKNOWN
                else -> throw IllegalArgumentException("Unhandled compatibility '$value' found.")
            }
    }
}

val matrix = mutableMapOf<Pair<String, String>, Compatibility>()

javaClass.getResourceAsStream("/osadl/osadl-matrix.csv").bufferedReader().useLines { lines ->
    val rowIterator = lines.iterator()

    // The first row contains the header with names of the inbound licenses.
    val columnHeaders = rowIterator.next().split(',')
        // Drop the surrounding "Compatibility*" cells from the header row.
        .drop(1).dropLast(1)

    while (rowIterator.hasNext()) {
        val cellIterator = rowIterator.next().split(',').iterator()

        // The first column contains the header with names of the outbound licenses.
        val inbound = cellIterator.next()

        columnHeaders.forEach { outbound ->
            val value = cellIterator.next()
            matrix[inbound to outbound] = Compatibility.fromString(value)
        }
    }
}

fun PackageRule.LicenseRule.isOsadlMatrixNonCompliant(inbound: String) =
    object : RuleMatcher {
        override val description = "isOsadlMatrixCompliant($license)"

        override fun matches(): Boolean {
            val outbound = license.toString()
            return matrix[inbound to outbound] == Compatibility.NO
        }
    }

val ruleSet = ruleSet(ortResult, licenseInfoResolver) {
    // Define a rule that is executed for each dependency.
    dependencyRule("OSADL compliance matrix") {
        // Requirements for the rule to trigger a violation.
        require {
            -isExcluded()
        }

        // Define a rule that is executed for each license of the dependency.
        val licenseView = LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED
        licenseRule("OSADL compliance matrix", licenseView) {
            // Use all licenses of all direct dependencies as inbound licenses.
            dependencies().forEach { dependency ->
                val resolveLicenseInfo = licenseInfoResolver.resolveLicenseInfo(dependency.id).filter(licenseView)
                val inboundLicenses = resolveLicenseInfo.licenses.map { it.license.toString() }

                inboundLicenses.forEach { inboundLicense ->
                    // Requirements for the rule to trigger a violation.
                    require {
                        +isOsadlMatrixNonCompliant(inboundLicense)
                    }

                    val pkgCoords = pkg.id.toCoordinates()
                    val depCoords = dependency.id.toCoordinates()

                    error(
                        "The outbound license '$license' of package '$pkgCoords' is incompatible " +
                                "with the inbound license '$inboundLicense' of its dependency '$depCoords'.",
                        "Remove the dependency on '$depCoords' or put '$pkgCoords' under a different license."
                    )
                }
            }
        }
    }
}

// Populate the list of errors to return.
ruleViolations += ruleSet.violations
