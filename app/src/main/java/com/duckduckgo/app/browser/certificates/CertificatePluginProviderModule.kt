/*
 * Copyright (c) 2020 DuckDuckGo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.duckduckgo.app.browser.certificates

import android.content.Context
import android.net.http.SslCertificate
import androidx.annotation.VisibleForTesting
import com.duckduckgo.app.browser.certificates.rootstore.*
import dagger.Module
import dagger.Provides
import java.security.cert.X509Certificate
import javax.inject.Singleton

interface LetsEncryptCertificateProvider {
    fun certificates(): List<LetsEncryptCertificate>

    fun findByCname(cname: String): LetsEncryptCertificate?
}

@VisibleForTesting
class LetsEncryptCertificateProviderImpl constructor(
    private val certificates: Set<LetsEncryptCertificate>
) : LetsEncryptCertificateProvider {
    override fun certificates(): List<LetsEncryptCertificate> {
        return certificates.toList()
    }

    override fun findByCname(cname: String): LetsEncryptCertificate? {
        return certificates
            .asSequence()
            .filter { SslCertificate(it.certificate() as X509Certificate).issuedTo.cName == cname }
            .firstOrNull()
    }
}

@Module
class CertificatePluginProviderModule {
    @Provides
    @Singleton
    fun provideLetsEncryptCertificateProvider(
        context: Context
    ): LetsEncryptCertificateProvider = LetsEncryptCertificateProviderImpl(
        setOf(
            IsrgRootX1(context),
            IsrgRootX2(context),
            LetsEncryptAuthorityX3(context),
            LetsEncryptR3(context),
            LetsEncryptE1(context)
        )
    )
}
