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

package org.ossreviewtoolkit.utils.test

import java.util.SortedSet

import org.ossreviewtoolkit.model.AnalyzerResult
import org.ossreviewtoolkit.model.AnalyzerRun
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.OrtResult
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageReference
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.Repository
import org.ossreviewtoolkit.model.Scope
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.utils.core.Environment
import org.ossreviewtoolkit.utils.spdx.toSpdx

@DslMarker
annotation class OrtResultDsl

@OrtResultDsl
class OrtResultBuilder {
    private val rootIds = mutableListOf<String>()
    private val parentChildIds = mutableMapOf<String, MutableList<String>>()

    private val packages = mutableListOf<Package>()

    @OrtResultDsl
    inner class PkgBuilder(private val id: String) {
        @OrtResultDsl
        var license = "Apache-2.0"

        @OrtResultDsl
        fun pkg(id: String, setup: PkgBuilder.() -> Unit): Package {
            this@OrtResultBuilder.parentChildIds.getOrPut(this@PkgBuilder.id) { mutableListOf() } += id
            val pkg = this@OrtResultBuilder.PkgBuilder(id).apply(setup).build()
            this@OrtResultBuilder.packages += pkg
            return pkg
        }

        fun build() = Package.EMPTY.copy(id = Identifier(id), concludedLicense = license.toSpdx())
    }

    @OrtResultDsl
    fun pkg(id: String, setup: PkgBuilder.() -> Unit): Package {
        rootIds += id
        val pkg = PkgBuilder(id).apply(setup).build()
        packages += pkg
        return pkg
    }

    private fun getDependencies(ids: List<String>): SortedSet<PackageReference> =
        ids.mapTo(sortedSetOf()) {
            PackageReference(
                id = Identifier(it),
                dependencies = getDependencies(parentChildIds[it].orEmpty())
            )
        }

    fun build(): OrtResult {
        val scope = Scope(
            name = "compile",
            dependencies = getDependencies(rootIds)
        )

        val projects = sortedSetOf(
            Project.EMPTY.copy(
                id = Identifier("Gradle:org.ossreviewtoolkit:project:1.0.0"),
                scopeDependencies = sortedSetOf(scope)
            )
        )

        return OrtResult(
            repository = Repository.EMPTY,
            analyzer = AnalyzerRun(
                environment = Environment(),
                config = AnalyzerConfiguration(),
                result = AnalyzerResult(
                    projects = projects,
                    packages = packages.mapTo(sortedSetOf()) { it.toCuratedPackage() }
                )
            )
        )
    }
}

@OrtResultDsl
fun ortResult(setup: OrtResultBuilder.() -> Unit) = OrtResultBuilder().apply(setup).build()
